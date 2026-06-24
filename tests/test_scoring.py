"""Tests for security score calculation.

Pure logic tests -- no AWS mocking needed.
"""

import unittest

from ecs_eks_security_scanner.utils import (
    calculate_ecs_security_score,
    calculate_eks_security_score,
)


class TestEcsSecurityScore(unittest.TestCase):
    """Test ECS security score calculation."""

    def _base_checks(self, **overrides):
        """All-pass ECS checks dict."""
        checks = {
            # A. Cluster Configuration
            "container_insights": {"enabled": True},
            "execute_command_logging": {
                "configured": True,
            },
            "cluster_encryption": {"kms_enabled": True},
            "capacity_provider_strategy": {
                "has_strategy": True,
            },
            "service_connect_namespace": {
                "configured": True,
            },
            # B. Task Definition Security
            "privileged_containers": {
                "has_privileged": False,
            },
            "root_user_containers": {
                "has_root_user": False,
            },
            "readonly_root_fs": {"all_readonly": True},
            "linux_capabilities": {
                "has_dangerous_caps": False,
            },
            "network_mode": {"all_awsvpc": True},
            "container_logging": {
                "all_configured": True,
            },
            "secrets_in_env": {
                "has_plaintext_secrets": False,
            },
            "resource_limits": {"all_defined": True},
            "pid_mode": {"has_host_pid": False},
            "execution_role": {"all_configured": True},
            # C. Service Security
            "ecs_exec_enabled": {"any_enabled": False},
            "public_ip_assignment": {
                "any_public": False,
            },
            "circuit_breaker": {"all_enabled": True},
            "fargate_platform_version": {
                "all_latest": True,
            },
            "service_security_groups": {
                "all_configured": True,
            },
            # F. IAM
            "role_separation": {"separated": True},
            "overly_permissive_roles": {
                "has_admin_roles": False,
            },
            "execution_policy_on_task": {
                "has_violation": False,
            },
            # G. Logging
            "guardduty_enabled": {"enabled": True},
            "vpc_flow_logs": {"enabled": True},
            # H. Data Protection
            "ecr_scan_on_push": {"all_enabled": True},
            "ecr_enhanced_scanning": {
                "enhanced_enabled": True,
            },
            "ecr_tag_immutability": {
                "all_immutable": True,
            },
            "in_transit_encryption": {
                "configured": True,
            },
        }
        checks.update(overrides)
        return checks

    def test_ecs_perfect_score(self):
        """All checks pass yields 100."""
        checks = self._base_checks()
        self.assertEqual(
            calculate_ecs_security_score(checks), 100
        )

    def test_ecs_worst_score(self):
        """All checks fail yields 0 (clamped)."""
        checks = self._base_checks(
            container_insights={"enabled": False},
            execute_command_logging={
                "configured": False,
            },
            cluster_encryption={"kms_enabled": False},
            capacity_provider_strategy={
                "has_strategy": False,
            },
            service_connect_namespace={
                "configured": False,
            },
            privileged_containers={
                "has_privileged": True,
            },
            root_user_containers={
                "has_root_user": True,
            },
            readonly_root_fs={"all_readonly": False},
            linux_capabilities={
                "has_dangerous_caps": True,
            },
            network_mode={"all_awsvpc": False},
            container_logging={
                "all_configured": False,
            },
            secrets_in_env={
                "has_plaintext_secrets": True,
            },
            resource_limits={"all_defined": False},
            pid_mode={"has_host_pid": True},
            execution_role={"all_configured": False},
            ecs_exec_enabled={"any_enabled": True},
            public_ip_assignment={"any_public": True},
            circuit_breaker={"all_enabled": False},
            fargate_platform_version={
                "all_latest": False,
            },
            service_security_groups={
                "all_configured": False,
            },
            role_separation={"separated": False},
            overly_permissive_roles={
                "has_admin_roles": True,
            },
            execution_policy_on_task={
                "has_violation": True,
            },
            guardduty_enabled={"enabled": False},
            vpc_flow_logs={"enabled": False},
            ecr_scan_on_push={"all_enabled": False},
            ecr_tag_immutability={
                "all_immutable": False,
            },
            in_transit_encryption={
                "configured": False,
            },
        )
        score = calculate_ecs_security_score(checks)
        self.assertEqual(score, 0)
        self.assertGreaterEqual(score, 0)

    def test_ecs_critical_deduction_b1(self):
        """B.1 privileged container deducts 20."""
        checks = self._base_checks(
            privileged_containers={
                "has_privileged": True,
            },
        )
        self.assertEqual(
            calculate_ecs_security_score(checks), 80
        )

    def test_ecs_c1_cross_reference(self):
        """C.1 exec enabled + A.2 logging configured = no penalty."""
        checks = self._base_checks(
            ecs_exec_enabled={"any_enabled": True},
            execute_command_logging={
                "configured": True,
            },
        )
        self.assertEqual(
            calculate_ecs_security_score(checks), 100
        )

    def test_ecs_c1_exec_with_no_logging(self):
        """C.1 exec enabled + A.2 no logging = penalty."""
        checks = self._base_checks(
            ecs_exec_enabled={"any_enabled": True},
            execute_command_logging={
                "configured": False,
            },
        )
        # -10 for A.2 + -5 for C.1 = 85
        self.assertEqual(
            calculate_ecs_security_score(checks), 85
        )

    def test_error_checks_skipped(self):
        """Check with 'error' key uses safe default."""
        checks = self._base_checks(
            container_insights={
                "error": "AccessDenied",
            },
        )
        score = calculate_ecs_security_score(checks)
        # error key present -> get() returns default False
        # -> not enabled -> -5
        self.assertLess(score, 100)

    def test_empty_checks(self):
        """Empty checks dict should not crash."""
        score = calculate_ecs_security_score({})
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


class TestEksSecurityScore(unittest.TestCase):
    """Test EKS security score calculation."""

    def _base_checks(self, **overrides):
        """All-pass EKS checks dict."""
        checks = {
            # D. EKS Cluster Configuration
            "endpoint_public_access": {
                "unrestricted": False,
            },
            "endpoint_private_access": {
                "enabled": True,
            },
            "secrets_encryption": {"enabled": True},
            "control_plane_logging": {
                "all_enabled": True,
            },
            "kubernetes_version_check": {
                "is_eol": False,
            },
            "cluster_security_group": {
                "configured": True,
            },
            "managed_addons": {"all_present": True},
            "fargate_profiles": {
                "has_profiles": False,
                "private_subnets_only": True,
            },
            # E. Node Group Security
            "nodegroup_remote_access": {
                "any_unrestricted": False,
            },
            "nodegroup_disk_encryption": {
                "all_encrypted": True,
            },
            "nodegroup_ami_type": {"all_secure": True},
            "nodegroup_launch_template": {
                "all_use_template": True,
            },
            # F. IAM
            "oidc_provider": {"configured": True},
            "overly_permissive_roles": {
                "has_admin_roles": False,
            },
            "cluster_role_permissions": {
                "overly_permissive": False,
            },
            # G. Logging
            "guardduty_enabled": {"enabled": True},
            "vpc_flow_logs": {"enabled": True},
            # H. Data Protection
            "ecr_scan_on_push": {"all_enabled": True},
            "ecr_enhanced_scanning": {
                "enhanced_enabled": True,
            },
            "ecr_tag_immutability": {
                "all_immutable": True,
            },
            "in_transit_encryption": {
                "configured": True,
            },
        }
        checks.update(overrides)
        return checks

    def test_eks_perfect_score(self):
        """All checks pass yields 100."""
        checks = self._base_checks()
        self.assertEqual(
            calculate_eks_security_score(checks), 100
        )

    def test_eks_worst_score(self):
        """All checks fail yields 0 (clamped)."""
        checks = self._base_checks(
            endpoint_public_access={
                "unrestricted": True,
            },
            endpoint_private_access={
                "enabled": False,
            },
            secrets_encryption={"enabled": False},
            control_plane_logging={
                "all_enabled": False,
            },
            kubernetes_version_check={"is_eol": True},
            cluster_security_group={
                "configured": False,
            },
            managed_addons={"all_present": False},
            fargate_profiles={
                "has_profiles": True,
                "private_subnets_only": False,
            },
            nodegroup_remote_access={
                "any_unrestricted": True,
            },
            nodegroup_disk_encryption={
                "all_encrypted": False,
            },
            nodegroup_ami_type={"all_secure": False},
            nodegroup_launch_template={
                "all_use_template": False,
            },
            oidc_provider={"configured": False},
            overly_permissive_roles={
                "has_admin_roles": True,
            },
            cluster_role_permissions={
                "overly_permissive": True,
            },
            guardduty_enabled={"enabled": False},
            vpc_flow_logs={"enabled": False},
            ecr_scan_on_push={"all_enabled": False},
            ecr_tag_immutability={
                "all_immutable": False,
            },
            in_transit_encryption={
                "configured": False,
            },
        )
        score = calculate_eks_security_score(checks)
        self.assertEqual(score, 0)
        self.assertGreaterEqual(score, 0)

    def test_eks_d8_fargate_no_profiles(self):
        """D.8 no Fargate profiles -> no penalty."""
        checks = self._base_checks(
            fargate_profiles={
                "has_profiles": False,
                "private_subnets_only": False,
            },
        )
        self.assertEqual(
            calculate_eks_security_score(checks), 100
        )

    def test_eks_d1_unrestricted_public(self):
        """D.1 unrestricted public access deducts 20."""
        checks = self._base_checks(
            endpoint_public_access={
                "unrestricted": True,
            },
        )
        self.assertEqual(
            calculate_eks_security_score(checks), 80
        )

    def test_eks_error_checks_skipped(self):
        """Check with 'error' key uses safe default."""
        checks = self._base_checks(
            secrets_encryption={
                "error": "AccessDenied",
            },
        )
        score = calculate_eks_security_score(checks)
        self.assertLess(score, 100)

    def test_eks_empty_checks(self):
        """Empty checks dict should not crash."""
        score = calculate_eks_security_score({})
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


if __name__ == "__main__":
    unittest.main()
