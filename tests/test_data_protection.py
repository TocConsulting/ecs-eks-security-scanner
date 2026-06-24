"""Tests for Data Protection Security Checker (H.2-H.4)."""

import unittest
from unittest.mock import Mock, MagicMock

from ecs_eks_security_scanner.checks.data_protection import (
    DataProtectionChecker,
)


class TestEcrScanOnPush(unittest.TestCase):
    """Test H.2 - ECR scan-on-push check."""

    def setUp(self):
        mock_session = Mock()
        self.mock_client = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = DataProtectionChecker(
            session_factory=lambda: mock_session
        )

    def test_ecr_scan_on_push_all(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [
                {
                    "repositoryName": "app",
                    "imageScanningConfiguration": {
                        "scanOnPush": True,
                    },
                },
                {
                    "repositoryName": "web",
                    "imageScanningConfiguration": {
                        "scanOnPush": True,
                    },
                },
            ],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_scan_on_push(
            "us-east-1"
        )
        self.assertTrue(result["all_enabled"])
        self.assertEqual(result["non_scanning_repos"], [])
        self.assertEqual(result["total_repos"], 2)

    def test_ecr_scan_on_push_some(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [
                {
                    "repositoryName": "app",
                    "imageScanningConfiguration": {
                        "scanOnPush": True,
                    },
                },
                {
                    "repositoryName": "web",
                    "imageScanningConfiguration": {
                        "scanOnPush": False,
                    },
                },
            ],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_scan_on_push(
            "us-east-1"
        )
        self.assertFalse(result["all_enabled"])
        self.assertIn(
            "web", result["non_scanning_repos"]
        )
        self.assertEqual(result["total_repos"], 2)

    def test_ecr_scan_on_push_no_repos(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_scan_on_push(
            "us-east-1"
        )
        self.assertTrue(result["all_enabled"])
        self.assertEqual(result["total_repos"], 0)

    def test_ecr_scan_on_push_missing_config(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [{
                "repositoryName": "app",
            }],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_scan_on_push(
            "us-east-1"
        )
        self.assertFalse(result["all_enabled"])
        self.assertIn(
            "app", result["non_scanning_repos"]
        )


class TestEcrTagImmutability(unittest.TestCase):
    """Test H.3 - ECR tag immutability check."""

    def setUp(self):
        mock_session = Mock()
        self.mock_client = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = DataProtectionChecker(
            session_factory=lambda: mock_session
        )

    def test_ecr_tag_immutability_all(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [
                {
                    "repositoryName": "app",
                    "imageTagMutability": "IMMUTABLE",
                },
                {
                    "repositoryName": "web",
                    "imageTagMutability": "IMMUTABLE",
                },
            ],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_tag_immutability(
            "us-east-1"
        )
        self.assertTrue(result["all_immutable"])
        self.assertEqual(result["mutable_repos"], [])
        self.assertEqual(result["total_repos"], 2)

    def test_ecr_tag_immutability_some(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [
                {
                    "repositoryName": "app",
                    "imageTagMutability": "IMMUTABLE",
                },
                {
                    "repositoryName": "web",
                    "imageTagMutability": "MUTABLE",
                },
            ],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_tag_immutability(
            "us-east-1"
        )
        self.assertFalse(result["all_immutable"])
        self.assertIn("web", result["mutable_repos"])

    def test_ecr_tag_immutability_no_repos(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_tag_immutability(
            "us-east-1"
        )
        self.assertTrue(result["all_immutable"])
        self.assertEqual(result["total_repos"], 0)

    def test_ecr_tag_immutability_default_mutable(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "repositories": [{
                "repositoryName": "app",
            }],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_ecr_tag_immutability(
            "us-east-1"
        )
        self.assertFalse(result["all_immutable"])


class TestInTransitEncryption(unittest.TestCase):
    """Test H.4 - In-transit encryption check.

    Current API: check_in_transit_encryption(
        cluster_arn, service_type, region).
    Queries ECS to inspect services in the cluster for
    Service Connect / load balancer presence.
    """

    def _build_checker(self):
        from unittest.mock import Mock
        mock_session = Mock()
        mock_ecs = Mock()
        mock_session.client.return_value = mock_ecs
        checker = DataProtectionChecker(
            session_factory=lambda: mock_session
        )
        return checker, mock_ecs

    def _wire_services(self, mock_ecs, services):
        from unittest.mock import MagicMock
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"serviceArns": [
                f"svc-{i}" for i in range(len(services))
            ]}
        ]
        mock_ecs.get_paginator.return_value = paginator
        mock_ecs.describe_services.return_value = {
            "services": services
        }

    def test_in_transit_encryption_configured(self):
        """Service Connect with TLS issuer set on every
        service counts as configured."""
        checker, mock_ecs = self._build_checker()
        self._wire_services(mock_ecs, [{
            "serviceConnectConfiguration": {
                "enabled": True,
                "services": [{
                    "portName": "web",
                    "tls": {
                        "issuerCertificateAuthority": {
                            "awsPcaAuthorityArn": (
                                "arn:aws:acm-pca:..."
                            ),
                        },
                    },
                }],
            },
            "loadBalancers": [],
        }])
        result = checker.check_in_transit_encryption(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertTrue(result["configured"])
        self.assertTrue(
            result["service_connect_enabled"]
        )

    def test_in_transit_encryption_sc_no_tls(self):
        """Service Connect enabled but without TLS issuer
        is NOT considered configured for in-transit."""
        checker, mock_ecs = self._build_checker()
        self._wire_services(mock_ecs, [{
            "serviceConnectConfiguration": {
                "enabled": True,
                "services": [{"portName": "web"}],
            },
            "loadBalancers": [],
        }])
        result = checker.check_in_transit_encryption(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertFalse(
            result["service_connect_enabled"]
        )

    def test_in_transit_encryption_lb(self):
        checker, mock_ecs = self._build_checker()
        self._wire_services(mock_ecs, [{
            "serviceConnectConfiguration": {
                "enabled": False,
            },
            "loadBalancers": [{
                "targetGroupArn": "arn:aws:...",
                "containerName": "web",
                "containerPort": 443,
            }],
        }])
        result = checker.check_in_transit_encryption(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertTrue(result["configured"])
        self.assertTrue(result["has_load_balancer"])

    def test_in_transit_encryption_not_configured(self):
        checker, mock_ecs = self._build_checker()
        self._wire_services(mock_ecs, [{
            "serviceConnectConfiguration": {
                "enabled": False,
            },
            "loadBalancers": [],
        }])
        result = checker.check_in_transit_encryption(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertFalse(result["configured"])
        self.assertFalse(
            result["service_connect_enabled"]
        )
        self.assertFalse(result["has_load_balancer"])

    def test_in_transit_encryption_empty(self):
        """No services in cluster - not configured."""
        checker, mock_ecs = self._build_checker()
        self._wire_services(mock_ecs, [])
        result = checker.check_in_transit_encryption(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertFalse(result["configured"])


if __name__ == "__main__":
    unittest.main()
