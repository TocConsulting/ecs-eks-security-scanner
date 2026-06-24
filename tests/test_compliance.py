"""Tests for compliance engine.

Pure logic tests -- no AWS mocking needed.
Note: compliance.py may still be under construction
by another agent. These tests assume ComplianceChecker
exists with a frameworks dict and
check_cluster_compliance method.
"""

import unittest

try:
    from ecs_eks_security_scanner.compliance import (
        ComplianceChecker,
    )
    HAS_COMPLIANCE = True
except ImportError:
    HAS_COMPLIANCE = False


@unittest.skipUnless(
    HAS_COMPLIANCE,
    "compliance.py not yet available",
)
class TestComplianceChecker(unittest.TestCase):
    """Test compliance framework evaluation."""

    def setUp(self):
        self.checker = ComplianceChecker()

    def _all_pass_ecs_checks(self):
        """All-pass ECS checks dict for compliance."""
        return {
            # A. Cluster
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
            # B. Task Definition
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
            # C. Service
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
            # D. EKS (not applicable)
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
                "has_profiles": True,
                "private_subnets_only": True,
            },
            # E. Node Group
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
            "role_separation": {"separated": True},
            "overly_permissive_roles": {
                "has_admin_roles": False,
            },
            "execution_policy_on_task": {
                "has_violation": False,
            },
            "oidc_provider": {"configured": True},
            "cluster_role_permissions": {
                "overly_permissive": False,
            },
            # G. Logging
            "guardduty_enabled": {"enabled": True},
            "vpc_flow_logs": {"enabled": True},
            # H. Data Protection
            "ecr_scan_on_push": {"all_enabled": True},
            "ecr_tag_immutability": {
                "all_immutable": True,
            },
            "in_transit_encryption": {
                "configured": True,
            },
        }

    def test_all_frameworks_present(self):
        """All 11 frameworks should be defined."""
        expected = [
            "AWS-FSBP", "CIS-EKS-v2.0", "EKS-Hardening",
            "PCI-DSS-v4.0.1", "HIPAA", "SOC2",
            "ISO27001", "ISO27017", "ISO27018",
            "GDPR", "NIST-800-53",
        ]
        for fw in expected:
            self.assertIn(
                fw, self.checker.frameworks,
                f"Missing framework: {fw}",
            )

    def test_total_controls(self):
        """Total control count should be 128."""
        total = sum(
            len(fw["controls"])
            for fw in self.checker.frameworks.values()
        )
        self.assertEqual(total, 128)

    def test_all_lambdas_callable(self):
        """All check lambdas should be callable."""
        for fw_id, fw in self.checker.frameworks.items():
            for ctrl_id, ctrl in fw["controls"].items():
                self.assertTrue(
                    callable(ctrl["check"]),
                    f"{fw_id}/{ctrl_id} not callable",
                )

    def test_all_lambdas_execute_without_error(self):
        """All lambdas should execute on empty dict."""
        for fw_id, fw in self.checker.frameworks.items():
            for ctrl_id, ctrl in fw["controls"].items():
                try:
                    result = ctrl["check"]({})
                    self.assertIsInstance(
                        result, bool,
                        f"{fw_id}/{ctrl_id} non-bool",
                    )
                except Exception as e:
                    self.fail(
                        f"{fw_id}/{ctrl_id} raised: {e}"
                    )

    def test_all_controls_have_applies_to(self):
        """Every control should have applies_to key."""
        for fw_id, fw in self.checker.frameworks.items():
            for ctrl_id, ctrl in fw["controls"].items():
                self.assertIn(
                    "applies_to", ctrl,
                    f"{fw_id}/{ctrl_id} missing "
                    "applies_to",
                )

    def test_ecs_only_controls_skipped_for_eks(self):
        """ECS-only controls should not fail EKS scan."""
        checks = self._all_pass_ecs_checks()
        compliance = (
            self.checker.check_cluster_compliance(
                checks, cluster_type="eks"
            )
        )
        for fw_id, result in compliance.items():
            for ctrl in result.get("failed", []):
                ctrl_def = (
                    self.checker.frameworks[fw_id]
                    ["controls"][ctrl["control_id"]]
                )
                applies = ctrl_def.get(
                    "applies_to", "both"
                )
                self.assertNotEqual(
                    applies, "ecs",
                    f"{fw_id}/{ctrl['control_id']} is "
                    "ECS-only but failed for EKS",
                )

    def test_eks_only_controls_skipped_for_ecs(self):
        """EKS-only controls should not fail ECS scan."""
        checks = self._all_pass_ecs_checks()
        compliance = (
            self.checker.check_cluster_compliance(
                checks, cluster_type="ecs"
            )
        )
        for fw_id, result in compliance.items():
            for ctrl in result.get("failed", []):
                ctrl_def = (
                    self.checker.frameworks[fw_id]
                    ["controls"][ctrl["control_id"]]
                )
                applies = ctrl_def.get(
                    "applies_to", "both"
                )
                self.assertNotEqual(
                    applies, "eks",
                    f"{fw_id}/{ctrl['control_id']} is "
                    "EKS-only but failed for ECS",
                )

    def test_both_controls_with_eks_only_keys_skipped_on_ecs(self):
        """Controls tagged 'both' whose lambda reads
        EKS-only top-level keys (e.g. endpoint_public_access)
        must be skipped - not failed - when run against an
        ECS-only cluster scan."""
        # A minimal ECS scan: only cross-service shared
        # keys populated. No endpoint_public_access etc.
        checks = {
            "guardduty_enabled": {"enabled": True},
            "vpc_flow_logs": {"enabled": True},
            "ecr_scan_on_push": {"all_enabled": True},
            "ecr_tag_immutability": {
                "all_immutable": True,
            },
            "in_transit_encryption": {
                "configured": True,
            },
        }
        compliance = (
            self.checker.check_cluster_compliance(
                checks, cluster_type="ecs"
            )
        )
        # PCI 1.3.1 reads endpoint_public_access (EKS-only)
        # + public_ip_assignment (ECS). On an ECS scan
        # without C.* data set, it should be skipped due
        # to the EKS-only key, NOT a failure.
        pci = compliance.get("PCI-DSS-v4.0.1", {})
        failed_ids = {
            c["control_id"] for c in pci.get("failed", [])
        }
        skipped_ids = {
            c["control_id"] for c in pci.get("skipped", [])
        }
        self.assertNotIn("1.3.1", failed_ids)
        self.assertIn("1.3.1", skipped_ids)

    def test_severity_matches_aws_security_hub(self):
        """FSBP severities must match the official AWS
        Security Hub values. Source:
        https://docs.aws.amazon.com/securityhub/latest/
        userguide/{ecs,eks}-controls.html"""
        expected = {
            "ECS.2": "HIGH",
            "ECS.3": "HIGH",
            "ECS.4": "HIGH",
            "ECS.5": "HIGH",
            "ECS.8": "HIGH",
            "ECS.9": "HIGH",
            "ECS.10": "MEDIUM",
            "ECS.12": "MEDIUM",
            "ECS.16": "HIGH",
            "ECS.17": "MEDIUM",
            "ECS.20": "MEDIUM",
            "EKS.1": "HIGH",
            "EKS.2": "HIGH",
            "EKS.3": "MEDIUM",
            "EKS.8": "MEDIUM",
            "EKS.9": "HIGH",
        }
        fsbp = self.checker.frameworks["AWS-FSBP"][
            "controls"
        ]
        for ctrl_id, expected_sev in expected.items():
            self.assertEqual(
                fsbp[ctrl_id]["severity"],
                expected_sev,
                f"FSBP {ctrl_id} severity mismatch",
            )

    def test_eks_hardening_framework_present(self):
        """EKS-Hardening framework holds AWS-specific node
        checks that were previously mis-numbered as CIS
        sections 3.1.1, 3.2.1, 3.2.2, 4.1.1, 4.2.1."""
        fw = self.checker.frameworks["EKS-Hardening"]
        ctrl_ids = set(fw["controls"].keys())
        self.assertEqual(
            ctrl_ids,
            {
                "NODE.SSH", "NODE.AMI", "NODE.DISK",
                "IAM.IRSA", "IAM.ROLE",
            },
        )

    def test_cis_eks_only_api_assessable_controls(self):
        """CIS-EKS-v2.0 should keep only the 5 controls
        that map to AWS API signals - the kubelet/RBAC
        sections require in-cluster inspection."""
        fw = self.checker.frameworks["CIS-EKS-v2.0"]
        ctrl_ids = set(fw["controls"].keys())
        self.assertEqual(
            ctrl_ids,
            {"2.1.1", "5.1.1", "5.3.1", "5.4.1", "5.4.2"},
        )

    def test_compliance_percentage_calculation(self):
        """Compliance percentage should be calculated."""
        checks = self._all_pass_ecs_checks()
        compliance = (
            self.checker.check_cluster_compliance(
                checks, cluster_type="ecs"
            )
        )
        for fw_id, result in compliance.items():
            pct = result.get("compliance_percentage", 0)
            self.assertIsInstance(pct, (int, float))
            self.assertGreaterEqual(pct, 0.0)
            self.assertLessEqual(pct, 100.0)
            total = result.get("total_controls", 0)
            passed = result.get("passed_controls", 0)
            failed = result.get("failed_controls", 0)
            self.assertEqual(total, passed + failed)


@unittest.skipUnless(
    HAS_COMPLIANCE,
    "compliance.py not yet available",
)
class TestFrameworkControlValidation(unittest.TestCase):
    """Validate each framework's control definitions."""

    def setUp(self):
        self.checker = ComplianceChecker()

    def test_all_controls_have_required_keys(self):
        """Every control must have description, severity, check."""
        for fw_id, fw in self.checker.frameworks.items():
            for ctrl_id, ctrl in fw["controls"].items():
                self.assertIn(
                    "description", ctrl,
                    f"{fw_id}/{ctrl_id} missing "
                    "description",
                )
                self.assertIn(
                    "severity", ctrl,
                    f"{fw_id}/{ctrl_id} missing "
                    "severity",
                )
                self.assertIn(
                    "check", ctrl,
                    f"{fw_id}/{ctrl_id} missing check",
                )

    def test_all_severities_are_valid(self):
        """All severities should be valid values."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for fw_id, fw in self.checker.frameworks.items():
            for ctrl_id, ctrl in fw["controls"].items():
                self.assertIn(
                    ctrl["severity"], valid,
                    f"{fw_id}/{ctrl_id} invalid "
                    f"severity: {ctrl['severity']}",
                )

    def test_compliance_result_structure(self):
        """Verify compliance result dict structure."""
        checks = {}
        compliance = (
            self.checker.check_cluster_compliance(
                checks, cluster_type="ecs"
            )
        )
        for fw_id, result in compliance.items():
            self.assertIn("framework_name", result)
            self.assertIn("total_controls", result)
            self.assertIn("passed_controls", result)
            self.assertIn("failed_controls", result)
            self.assertIn("compliance_percentage", result)
            self.assertIn("is_compliant", result)
            self.assertIn("passed", result)
            self.assertIn("failed", result)

    def test_empty_checks_does_not_crash(self):
        """Empty checks should not crash evaluation."""
        compliance = (
            self.checker.check_cluster_compliance(
                {}, cluster_type="ecs"
            )
        )
        self.assertIsInstance(compliance, dict)


if __name__ == "__main__":
    unittest.main()
