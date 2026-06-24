"""Tests for IAM Security Checker (F.1-F.5)."""

import unittest
from unittest.mock import Mock, MagicMock, patch

from ecs_eks_security_scanner.checks.iam_security import (
    IAMSecurityChecker,
)


def _build_checker_with_iam():
    """Helper: IAMSecurityChecker wired with a Mock IAM client."""
    mock_session = Mock()
    mock_iam = Mock()
    mock_ecs = Mock()
    mock_eks = Mock()

    def client(service_name, **kwargs):
        return {
            "iam": mock_iam,
            "ecs": mock_ecs,
            "eks": mock_eks,
        }[service_name]

    mock_session.client.side_effect = client
    checker = IAMSecurityChecker(
        session_factory=lambda: mock_session
    )
    return checker, mock_iam, mock_ecs, mock_eks


class TestRoleSeparation(unittest.TestCase):
    """Test F.1 - Role separation check.

    Current API: check_role_separation(cluster_arn, region).
    The method queries ECS for task definitions used by
    services in the cluster.
    """

    def _setup_ecs_task_defs(self, mock_ecs, task_defs):
        """Wire up the ECS mocks to return given task defs."""
        svc_paginator = MagicMock()
        svc_paginator.paginate.return_value = [
            {"serviceArns": [f"svc-{i}" for i in range(len(task_defs))]}
        ]
        mock_ecs.get_paginator.return_value = svc_paginator
        mock_ecs.describe_services.return_value = {
            "services": [
                {"taskDefinition": f"td-arn-{i}"}
                for i, _ in enumerate(task_defs)
            ]
        }
        mock_ecs.describe_task_definition.side_effect = [
            {"taskDefinition": td} for td in task_defs
        ]

    def test_role_separation_separated(self):
        checker, _, mock_ecs, _ = _build_checker_with_iam()
        self._setup_ecs_task_defs(mock_ecs, [{
            "taskDefinitionArn": "td1",
            "taskRoleArn": "arn:aws:iam::123:role/taskRole",
            "executionRoleArn": (
                "arn:aws:iam::123:role/execRole"
            ),
        }])
        result = checker.check_role_separation(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "us-east-1",
        )
        self.assertTrue(result["separated"])

    def test_role_separation_same(self):
        checker, _, mock_ecs, _ = _build_checker_with_iam()
        arn = "arn:aws:iam::123:role/sharedRole"
        self._setup_ecs_task_defs(mock_ecs, [{
            "taskDefinitionArn": "td1",
            "taskRoleArn": arn,
            "executionRoleArn": arn,
        }])
        result = checker.check_role_separation(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "us-east-1",
        )
        self.assertFalse(result["separated"])
        self.assertEqual(len(result["violations"]), 1)

    def test_role_separation_no_task_defs(self):
        checker, _, mock_ecs, _ = _build_checker_with_iam()
        # No services in cluster
        svc_paginator = MagicMock()
        svc_paginator.paginate.return_value = [
            {"serviceArns": []}
        ]
        mock_ecs.get_paginator.return_value = svc_paginator
        result = checker.check_role_separation(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "us-east-1",
        )
        self.assertTrue(result["separated"])
        self.assertEqual(
            result["task_definitions_checked"], 0
        )

    def test_role_separation_missing_task_role(self):
        """taskRole missing - treated as compliant (no
        violation can be evaluated)."""
        checker, _, mock_ecs, _ = _build_checker_with_iam()
        self._setup_ecs_task_defs(mock_ecs, [{
            "taskDefinitionArn": "td1",
            "executionRoleArn": (
                "arn:aws:iam::123:role/execRole"
            ),
        }])
        result = checker.check_role_separation(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "us-east-1",
        )
        self.assertTrue(result["separated"])


class TestOverlyPermissiveRoles(unittest.TestCase):
    """Test F.2 - Overly permissive roles (admin / wildcard)."""

    def _wire_one_ecs_role(self, checker, mock_ecs, role_arn):
        """Set up a cluster with one service using one task def
        that references role_arn as taskRoleArn."""
        svc_paginator = MagicMock()
        svc_paginator.paginate.return_value = [
            {"serviceArns": ["svc1"]}
        ]
        mock_ecs.get_paginator.return_value = svc_paginator
        mock_ecs.describe_services.return_value = {
            "services": [{"taskDefinition": "td-arn"}]
        }
        mock_ecs.describe_task_definition.return_value = {
            "taskDefinition": {
                "taskDefinitionArn": "td-arn",
                "taskRoleArn": role_arn,
            }
        }

    def test_admin_managed_policy(self):
        checker, mock_iam, mock_ecs, _ = (
            _build_checker_with_iam()
        )
        role_arn = "arn:aws:iam::123:role/myRole"
        self._wire_one_ecs_role(checker, mock_ecs, role_arn)

        attached_paginator = MagicMock()
        attached_paginator.paginate.return_value = [{
            "AttachedPolicies": [{
                "PolicyName": "AdministratorAccess",
                "PolicyArn": (
                    "arn:aws:iam::aws:policy/"
                    "AdministratorAccess"
                ),
            }],
        }]
        inline_paginator = MagicMock()
        inline_paginator.paginate.return_value = [{
            "PolicyNames": [],
        }]
        mock_iam.get_paginator.side_effect = (
            lambda name: {
                "list_attached_role_policies": (
                    attached_paginator
                ),
                "list_role_policies": inline_paginator,
            }[name]
        )

        result = checker.check_overly_permissive_roles(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertTrue(result["has_admin_roles"])
        self.assertTrue(result["overly_permissive"])

    def test_clean_role(self):
        checker, mock_iam, mock_ecs, _ = (
            _build_checker_with_iam()
        )
        role_arn = "arn:aws:iam::123:role/myRole"
        self._wire_one_ecs_role(checker, mock_ecs, role_arn)

        attached_paginator = MagicMock()
        attached_paginator.paginate.return_value = [{
            "AttachedPolicies": [{
                "PolicyName": "ReadOnlyAccess",
                "PolicyArn": (
                    "arn:aws:iam::aws:policy/"
                    "ReadOnlyAccess"
                ),
            }],
        }]
        inline_paginator = MagicMock()
        inline_paginator.paginate.return_value = [{
            "PolicyNames": [],
        }]
        mock_iam.get_paginator.side_effect = (
            lambda name: {
                "list_attached_role_policies": (
                    attached_paginator
                ),
                "list_role_policies": inline_paginator,
            }[name]
        )

        result = checker.check_overly_permissive_roles(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertFalse(result["has_admin_roles"])
        self.assertFalse(result["overly_permissive"])

    def test_wildcard_inline_policy(self):
        checker, mock_iam, mock_ecs, _ = (
            _build_checker_with_iam()
        )
        role_arn = "arn:aws:iam::123:role/myRole"
        self._wire_one_ecs_role(checker, mock_ecs, role_arn)

        attached_paginator = MagicMock()
        attached_paginator.paginate.return_value = [{
            "AttachedPolicies": [],
        }]
        inline_paginator = MagicMock()
        inline_paginator.paginate.return_value = [{
            "PolicyNames": ["inline-policy"],
        }]
        mock_iam.get_paginator.side_effect = (
            lambda name: {
                "list_attached_role_policies": (
                    attached_paginator
                ),
                "list_role_policies": inline_paginator,
            }[name]
        )
        mock_iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }],
            },
        }

        result = checker.check_overly_permissive_roles(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertTrue(result["has_admin_roles"])
        self.assertTrue(result["overly_permissive"])

    def test_no_services(self):
        """Cluster with no services - no roles to check."""
        checker, _, mock_ecs, _ = _build_checker_with_iam()
        svc_paginator = MagicMock()
        svc_paginator.paginate.return_value = [
            {"serviceArns": []}
        ]
        mock_ecs.get_paginator.return_value = svc_paginator
        result = checker.check_overly_permissive_roles(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "ecs", "us-east-1",
        )
        self.assertFalse(result["has_admin_roles"])


class TestOidcProvider(unittest.TestCase):
    """Test F.3 - OIDC provider check."""

    def test_oidc_provider_configured(self):
        checker, mock_iam, _, _ = _build_checker_with_iam()
        cluster = {
            "identity": {
                "oidc": {
                    "issuer": (
                        "https://oidc.eks.us-east-1"
                        ".amazonaws.com/id/ABCDEF"
                    ),
                }
            }
        }
        mock_iam.list_open_id_connect_providers.return_value = {
            "OpenIDConnectProviderList": [{
                "Arn": (
                    "arn:aws:iam::123:oidc-provider/"
                    "oidc.eks.us-east-1.amazonaws.com"
                    "/id/ABCDEF"
                ),
            }],
        }
        result = checker.check_oidc_provider(
            cluster, "us-east-1"
        )
        self.assertTrue(result["configured"])
        self.assertTrue(result["has_iam_provider"])

    def test_oidc_provider_not_configured(self):
        checker, _, _, _ = _build_checker_with_iam()
        cluster = {}
        result = checker.check_oidc_provider(
            cluster, "us-east-1"
        )
        self.assertFalse(result["configured"])
        self.assertIsNone(result["issuer_url"])

    def test_oidc_provider_issuer_no_match(self):
        checker, mock_iam, _, _ = _build_checker_with_iam()
        cluster = {
            "identity": {
                "oidc": {
                    "issuer": (
                        "https://oidc.eks.us-east-1"
                        ".amazonaws.com/id/XYZ"
                    ),
                }
            }
        }
        mock_iam.list_open_id_connect_providers.return_value = {
            "OpenIDConnectProviderList": [{
                "Arn": (
                    "arn:aws:iam::123:oidc-provider/"
                    "oidc.eks.us-west-2.amazonaws.com"
                    "/id/OTHER"
                ),
            }],
        }
        result = checker.check_oidc_provider(
            cluster, "us-east-1"
        )
        self.assertFalse(result["configured"])


class TestExecutionPolicyOnTask(unittest.TestCase):
    """Test F.4 - Execution policy on task role.

    Current API: check_execution_policy_on_task(
        cluster_arn, region).
    """

    def _wire(self, mock_ecs, task_role_arn):
        svc_paginator = MagicMock()
        svc_paginator.paginate.return_value = [
            {"serviceArns": ["svc1"]}
        ]
        mock_ecs.get_paginator.return_value = svc_paginator
        mock_ecs.describe_services.return_value = {
            "services": [{"taskDefinition": "td1"}]
        }
        td = {
            "taskDefinitionArn": "td1",
        }
        if task_role_arn:
            td["taskRoleArn"] = task_role_arn
        mock_ecs.describe_task_definition.return_value = {
            "taskDefinition": td
        }

    def test_violation(self):
        checker, mock_iam, mock_ecs, _ = (
            _build_checker_with_iam()
        )
        self._wire(
            mock_ecs, "arn:aws:iam::123:role/taskRole"
        )
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "AttachedPolicies": [{
                "PolicyName": (
                    "AmazonECSTaskExecutionRolePolicy"
                ),
                "PolicyArn": (
                    "arn:aws:iam::aws:policy/"
                    "service-role/"
                    "AmazonECSTaskExecutionRolePolicy"
                ),
            }],
        }]
        mock_iam.get_paginator.return_value = paginator
        result = checker.check_execution_policy_on_task(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "us-east-1",
        )
        self.assertTrue(result["has_violation"])

    def test_clean(self):
        checker, mock_iam, mock_ecs, _ = (
            _build_checker_with_iam()
        )
        self._wire(
            mock_ecs, "arn:aws:iam::123:role/taskRole"
        )
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "AttachedPolicies": [{
                "PolicyName": "CustomAppPolicy",
                "PolicyArn": (
                    "arn:aws:iam::123:policy/CustomApp"
                ),
            }],
        }]
        mock_iam.get_paginator.return_value = paginator
        result = checker.check_execution_policy_on_task(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "us-east-1",
        )
        self.assertFalse(result["has_violation"])

    def test_no_task_role(self):
        checker, _, mock_ecs, _ = _build_checker_with_iam()
        self._wire(mock_ecs, None)
        result = checker.check_execution_policy_on_task(
            "arn:aws:ecs:us-east-1:123:cluster/c1",
            "us-east-1",
        )
        self.assertFalse(result["has_violation"])


if __name__ == "__main__":
    unittest.main()
