"""Tests for EKS Node Group Security Checker (E.1-E.4)."""

import unittest

from ecs_eks_security_scanner.checks.eks_nodegroup import (
    EKSNodeGroupChecker,
)


class TestRemoteAccess(unittest.TestCase):
    """Test E.1 - Remote access check."""

    def setUp(self):
        self.checker = EKSNodeGroupChecker()

    def test_remote_access_unrestricted(self):
        nodegroup = {
            "remoteAccess": {
                "ec2SshKey": "my-key",
                "sourceSecurityGroups": [],
            }
        }
        result = self.checker.check_remote_access(
            nodegroup
        )
        self.assertTrue(result["has_remote_access"])
        self.assertTrue(result["unrestricted"])

    def test_remote_access_restricted(self):
        nodegroup = {
            "remoteAccess": {
                "ec2SshKey": "my-key",
                "sourceSecurityGroups": ["sg-abc123"],
            }
        }
        result = self.checker.check_remote_access(
            nodegroup
        )
        self.assertTrue(result["has_remote_access"])
        self.assertFalse(result["unrestricted"])

    def test_remote_access_none(self):
        nodegroup = {}
        result = self.checker.check_remote_access(
            nodegroup
        )
        self.assertFalse(result["has_remote_access"])
        self.assertFalse(result["unrestricted"])

    def test_remote_access_empty_dict(self):
        nodegroup = {"remoteAccess": {}}
        result = self.checker.check_remote_access(
            nodegroup
        )
        self.assertFalse(result["has_remote_access"])
        self.assertFalse(result["unrestricted"])


class TestDiskEncryption(unittest.TestCase):
    """Test E.2 - Disk encryption check.

    The check inspects the launch template's
    BlockDeviceMappings when present, or queries
    ec2:GetEbsEncryptionByDefault otherwise. Without a
    region the check returns encrypted=False as a safe
    default.
    """

    def _checker_with_ec2(self):
        from unittest.mock import Mock
        mock_session = Mock()
        mock_ec2 = Mock()
        mock_session.client.return_value = mock_ec2
        checker = EKSNodeGroupChecker(
            session_factory=lambda: mock_session
        )
        return checker, mock_ec2

    def test_disk_encryption_with_template_encrypted(self):
        checker, mock_ec2 = self._checker_with_ec2()
        nodegroup = {
            "diskSize": 100,
            "launchTemplate": {
                "id": "lt-abc123",
                "version": "1",
            },
        }
        mock_ec2.describe_launch_template_versions.return_value = {
            "LaunchTemplateVersions": [{
                "LaunchTemplateData": {
                    "BlockDeviceMappings": [{
                        "Ebs": {"Encrypted": True},
                    }],
                },
            }],
        }
        result = checker.check_disk_encryption(
            nodegroup, "us-east-1"
        )
        self.assertTrue(result["encrypted"])
        self.assertTrue(result["uses_launch_template"])

    def test_disk_encryption_with_template_unencrypted(self):
        checker, mock_ec2 = self._checker_with_ec2()
        nodegroup = {
            "launchTemplate": {
                "id": "lt-abc123",
                "version": "1",
            },
        }
        mock_ec2.describe_launch_template_versions.return_value = {
            "LaunchTemplateVersions": [{
                "LaunchTemplateData": {
                    "BlockDeviceMappings": [{
                        "Ebs": {"Encrypted": False},
                    }],
                },
            }],
        }
        result = checker.check_disk_encryption(
            nodegroup, "us-east-1"
        )
        self.assertFalse(result["encrypted"])

    def test_disk_encryption_no_template_default_on(self):
        """No launch template, EBS default encryption is on."""
        checker, mock_ec2 = self._checker_with_ec2()
        nodegroup = {"diskSize": 100}
        mock_ec2.get_ebs_encryption_by_default.return_value = {
            "EbsEncryptionByDefault": True
        }
        result = checker.check_disk_encryption(
            nodegroup, "us-east-1"
        )
        self.assertTrue(result["encrypted"])
        self.assertFalse(result["uses_launch_template"])

    def test_disk_encryption_no_template_default_off(self):
        """No launch template, EBS default encryption is off."""
        checker, mock_ec2 = self._checker_with_ec2()
        nodegroup = {"diskSize": 100}
        mock_ec2.get_ebs_encryption_by_default.return_value = {
            "EbsEncryptionByDefault": False
        }
        result = checker.check_disk_encryption(
            nodegroup, "us-east-1"
        )
        self.assertFalse(result["encrypted"])

    def test_disk_encryption_no_region(self):
        """Without region, cannot inspect - safe default off."""
        nodegroup = {"diskSize": 100}
        result = (
            EKSNodeGroupChecker().check_disk_encryption(
                nodegroup
            )
        )
        self.assertFalse(result["encrypted"])


class TestAmiType(unittest.TestCase):
    """Test E.3 - AMI type check."""

    def setUp(self):
        self.checker = EKSNodeGroupChecker()

    def test_ami_type_secure(self):
        nodegroup = {
            "amiType": "BOTTLEROCKET_x86_64",
        }
        result = self.checker.check_ami_type(nodegroup)
        self.assertTrue(result["is_secure"])
        self.assertEqual(
            result["ami_type"], "BOTTLEROCKET_x86_64"
        )

    def test_ami_type_al2023(self):
        nodegroup = {
            "amiType": "AL2023_x86_64_STANDARD",
        }
        result = self.checker.check_ami_type(nodegroup)
        self.assertTrue(result["is_secure"])

    def test_ami_type_insecure(self):
        nodegroup = {"amiType": "AL2_x86_64"}
        result = self.checker.check_ami_type(nodegroup)
        self.assertFalse(result["is_secure"])
        self.assertEqual(
            result["ami_type"], "AL2_x86_64"
        )

    def test_ami_type_custom(self):
        nodegroup = {"amiType": "CUSTOM"}
        result = self.checker.check_ami_type(nodegroup)
        self.assertFalse(result["is_secure"])

    def test_ami_type_not_set(self):
        nodegroup = {}
        result = self.checker.check_ami_type(nodegroup)
        self.assertFalse(result["is_secure"])


class TestLaunchTemplate(unittest.TestCase):
    """Test E.4 - Launch template presence check."""

    def setUp(self):
        self.checker = EKSNodeGroupChecker()

    def test_launch_template_present(self):
        nodegroup = {
            "launchTemplate": {
                "id": "lt-abc123",
                "name": "my-template",
                "version": "3",
            }
        }
        result = self.checker.check_launch_template(
            nodegroup
        )
        self.assertTrue(result["has_launch_template"])
        self.assertEqual(
            result["template_id"], "lt-abc123"
        )
        self.assertEqual(
            result["template_name"], "my-template"
        )
        self.assertEqual(result["template_version"], "3")

    def test_launch_template_missing(self):
        nodegroup = {}
        result = self.checker.check_launch_template(
            nodegroup
        )
        self.assertFalse(result["has_launch_template"])
        self.assertIsNone(result["template_id"])
        self.assertIsNone(result["template_name"])

    def test_launch_template_empty(self):
        nodegroup = {"launchTemplate": {}}
        result = self.checker.check_launch_template(
            nodegroup
        )
        self.assertFalse(result["has_launch_template"])

    def test_launch_template_by_name_only(self):
        nodegroup = {
            "launchTemplate": {
                "name": "my-template",
            }
        }
        result = self.checker.check_launch_template(
            nodegroup
        )
        self.assertTrue(result["has_launch_template"])


if __name__ == "__main__":
    unittest.main()
