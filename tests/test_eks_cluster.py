"""Tests for EKS Cluster Security Checker (D.1-D.8)."""

import unittest
from unittest.mock import Mock, MagicMock

from ecs_eks_security_scanner.checks.eks_cluster import (
    EKSClusterChecker,
)


class TestEndpointPublicAccess(unittest.TestCase):
    """Test D.1 - Endpoint public access check."""

    def setUp(self):
        self.checker = EKSClusterChecker()

    def test_endpoint_public_unrestricted(self):
        cluster = {
            "resourcesVpcConfig": {
                "endpointPublicAccess": True,
                "publicAccessCidrs": ["0.0.0.0/0"],
            }
        }
        result = (
            self.checker.check_endpoint_public_access(
                cluster
            )
        )
        self.assertTrue(result["public"])
        self.assertTrue(result["unrestricted"])

    def test_endpoint_public_restricted(self):
        cluster = {
            "resourcesVpcConfig": {
                "endpointPublicAccess": True,
                "publicAccessCidrs": ["10.0.0.0/8"],
            }
        }
        result = (
            self.checker.check_endpoint_public_access(
                cluster
            )
        )
        self.assertTrue(result["public"])
        self.assertFalse(result["unrestricted"])

    def test_endpoint_public_disabled(self):
        cluster = {
            "resourcesVpcConfig": {
                "endpointPublicAccess": False,
                "publicAccessCidrs": [],
            }
        }
        result = (
            self.checker.check_endpoint_public_access(
                cluster
            )
        )
        self.assertFalse(result["public"])
        self.assertFalse(result["unrestricted"])


class TestEndpointPrivateAccess(unittest.TestCase):
    """Test D.2 - Endpoint private access check."""

    def setUp(self):
        self.checker = EKSClusterChecker()

    def test_endpoint_private_enabled(self):
        cluster = {
            "resourcesVpcConfig": {
                "endpointPrivateAccess": True,
            }
        }
        result = (
            self.checker.check_endpoint_private_access(
                cluster
            )
        )
        self.assertTrue(result["enabled"])

    def test_endpoint_private_disabled(self):
        cluster = {
            "resourcesVpcConfig": {
                "endpointPrivateAccess": False,
            }
        }
        result = (
            self.checker.check_endpoint_private_access(
                cluster
            )
        )
        self.assertFalse(result["enabled"])

    def test_endpoint_private_not_set(self):
        cluster = {}
        result = (
            self.checker.check_endpoint_private_access(
                cluster
            )
        )
        self.assertFalse(result["enabled"])


class TestSecretsEncryption(unittest.TestCase):
    """Test D.3 - Secrets encryption check."""

    def setUp(self):
        self.checker = EKSClusterChecker()

    def test_secrets_encryption_enabled(self):
        cluster = {
            "encryptionConfig": [{
                "resources": ["secrets"],
                "provider": {
                    "keyArn": (
                        "arn:aws:kms:us-east-1:"
                        "123:key/abc"
                    ),
                },
            }]
        }
        result = (
            self.checker.check_secrets_encryption(cluster)
        )
        self.assertTrue(result["enabled"])
        self.assertIsNotNone(result["kms_key_arn"])

    def test_secrets_encryption_disabled(self):
        cluster = {}
        result = (
            self.checker.check_secrets_encryption(cluster)
        )
        self.assertFalse(result["enabled"])
        self.assertIsNone(result["kms_key_arn"])

    def test_encryption_config_no_secrets(self):
        cluster = {
            "encryptionConfig": [{
                "resources": ["configmaps"],
                "provider": {"keyArn": "arn:aws:kms:key"},
            }]
        }
        result = (
            self.checker.check_secrets_encryption(cluster)
        )
        self.assertFalse(result["enabled"])


class TestControlPlaneLogging(unittest.TestCase):
    """Test D.4 - Control plane logging check."""

    def setUp(self):
        self.checker = EKSClusterChecker()

    def test_control_plane_logging_all(self):
        cluster = {
            "logging": {
                "clusterLogging": [{
                    "types": [
                        "api", "audit", "authenticator",
                        "controllerManager", "scheduler",
                    ],
                    "enabled": True,
                }]
            }
        }
        result = (
            self.checker.check_control_plane_logging(
                cluster
            )
        )
        self.assertTrue(result["all_enabled"])
        self.assertEqual(result["missing_types"], [])

    def test_control_plane_logging_partial(self):
        cluster = {
            "logging": {
                "clusterLogging": [{
                    "types": ["api", "audit"],
                    "enabled": True,
                }]
            }
        }
        result = (
            self.checker.check_control_plane_logging(
                cluster
            )
        )
        self.assertFalse(result["all_enabled"])
        self.assertIn(
            "authenticator", result["missing_types"]
        )

    def test_control_plane_logging_none(self):
        cluster = {}
        result = (
            self.checker.check_control_plane_logging(
                cluster
            )
        )
        self.assertFalse(result["all_enabled"])
        self.assertEqual(len(result["missing_types"]), 5)

    def test_control_plane_logging_disabled(self):
        cluster = {
            "logging": {
                "clusterLogging": [{
                    "types": [
                        "api", "audit", "authenticator",
                        "controllerManager", "scheduler",
                    ],
                    "enabled": False,
                }]
            }
        }
        result = (
            self.checker.check_control_plane_logging(
                cluster
            )
        )
        self.assertFalse(result["all_enabled"])


class TestKubernetesVersion(unittest.TestCase):
    """Test D.5 - Kubernetes version check."""

    def setUp(self):
        self.checker = EKSClusterChecker()

    def test_kubernetes_version_standard_support(self):
        cluster = {"version": "1.33"}
        result = (
            self.checker.check_kubernetes_version(cluster)
        )
        self.assertTrue(result["supported"])
        self.assertFalse(result["is_eol"])
        self.assertFalse(result["extended_support"])

    def test_kubernetes_version_extended_support(self):
        """Versions in extended support are still
        supported by AWS (paid) - not EOL - but flagged
        with extended_support=True for HIGH severity."""
        cluster = {"version": "1.30"}
        result = (
            self.checker.check_kubernetes_version(cluster)
        )
        self.assertFalse(result["supported"])
        self.assertFalse(result["is_eol"])
        self.assertTrue(result["extended_support"])

    def test_kubernetes_version_eol(self):
        cluster = {"version": "1.24"}
        result = (
            self.checker.check_kubernetes_version(cluster)
        )
        self.assertFalse(result["supported"])
        self.assertTrue(result["is_eol"])

    def test_kubernetes_version_missing(self):
        cluster = {}
        result = (
            self.checker.check_kubernetes_version(cluster)
        )
        self.assertFalse(result["supported"])
        self.assertTrue(result["is_eol"])


class TestClusterSecurityGroup(unittest.TestCase):
    """Test D.6 - Cluster security group check."""

    def setUp(self):
        self.checker = EKSClusterChecker()

    def test_cluster_security_group_present(self):
        cluster = {
            "resourcesVpcConfig": {
                "clusterSecurityGroupId": "sg-abc123",
            }
        }
        result = (
            self.checker.check_cluster_security_group(
                cluster
            )
        )
        self.assertTrue(result["configured"])
        self.assertEqual(
            result["security_group_id"], "sg-abc123"
        )

    def test_cluster_security_group_missing(self):
        cluster = {"resourcesVpcConfig": {}}
        result = (
            self.checker.check_cluster_security_group(
                cluster
            )
        )
        self.assertFalse(result["configured"])
        self.assertIsNone(result["security_group_id"])


class TestManagedAddons(unittest.TestCase):
    """Test D.7 - Managed add-ons check (uses paginator)."""

    def setUp(self):
        mock_session = Mock()
        self.mock_client = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = EKSClusterChecker(
            session_factory=lambda: mock_session
        )

    def test_managed_addons_all(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "addons": [
                "vpc-cni", "kube-proxy", "coredns",
            ],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_managed_addons(
            "my-cluster", "us-east-1"
        )
        self.assertTrue(result["all_present"])
        self.assertEqual(result["missing_addons"], [])

    def test_managed_addons_missing(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "addons": ["vpc-cni"],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_managed_addons(
            "my-cluster", "us-east-1"
        )
        self.assertFalse(result["all_present"])
        self.assertIn(
            "kube-proxy", result["missing_addons"]
        )
        self.assertIn("coredns", result["missing_addons"])

    def test_managed_addons_none(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"addons": []}]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_managed_addons(
            "my-cluster", "us-east-1"
        )
        self.assertFalse(result["all_present"])
        self.assertEqual(len(result["missing_addons"]), 3)


class TestFargateProfiles(unittest.TestCase):
    """Test D.8 - Fargate profiles check (paginator)."""

    def setUp(self):
        mock_session = Mock()
        self.mock_client = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = EKSClusterChecker(
            session_factory=lambda: mock_session
        )

    def test_fargate_profiles_present(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "fargateProfileNames": ["fp-default"],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        self.mock_client.describe_fargate_profile.return_value = {
            "fargateProfile": {
                "fargateProfileName": "fp-default",
                "subnets": ["subnet-priv1"],
            }
        }
        # The check also calls ec2:DescribeSubnets to
        # verify subnets are private. Wire that up too:
        # the session mock returns the same client for
        # all service names in this test.
        self.mock_client.describe_subnets.return_value = {
            "Subnets": [{
                "SubnetId": "subnet-priv1",
                "MapPublicIpOnLaunch": False,
            }]
        }
        result = self.checker.check_fargate_profiles(
            "my-cluster", "us-east-1"
        )
        self.assertTrue(result["has_profiles"])
        self.assertEqual(result["profile_count"], 1)
        self.assertTrue(result["private_subnets_only"])

    def test_fargate_profiles_none(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "fargateProfileNames": [],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_fargate_profiles(
            "my-cluster", "us-east-1"
        )
        self.assertFalse(result["has_profiles"])
        self.assertEqual(result["profile_count"], 0)
        self.assertTrue(result["private_subnets_only"])


if __name__ == "__main__":
    unittest.main()
