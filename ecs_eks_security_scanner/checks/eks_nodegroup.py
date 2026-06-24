"""EKS Node Group Security Checker - E.1-E.4."""

from typing import Dict, Any

from botocore.exceptions import ClientError

from .base import BaseChecker


class EKSNodeGroupChecker(BaseChecker):
    """Check EKS node group security configuration."""

    # All valid AL2023 / Bottlerocket amiType values per
    # https://docs.aws.amazon.com/eks/latest/APIReference/
    # API_Nodegroup.html#AmazonEKS-Type-Nodegroup-amiType.
    # AL2 (Amazon Linux 2) variants intentionally excluded -
    # EKS AL2 support ended 2025-11-26.
    SECURE_AMI_TYPES = [
        "AL2023_x86_64_STANDARD",
        "AL2023_ARM_64_STANDARD",
        "AL2023_x86_64_NEURON",
        "AL2023_x86_64_NVIDIA",
        "AL2023_ARM_64_NVIDIA",
        "BOTTLEROCKET_x86_64",
        "BOTTLEROCKET_ARM_64",
        "BOTTLEROCKET_x86_64_NVIDIA",
        "BOTTLEROCKET_ARM_64_NVIDIA",
        "BOTTLEROCKET_x86_64_FIPS",
        "BOTTLEROCKET_ARM_64_FIPS",
    ]

    def check_remote_access(
        self, nodegroup: Dict[str, Any]
    ) -> Dict[str, Any]:
        """E.1 - Check SSH key and source security groups."""
        try:
            remote_access = nodegroup.get("remoteAccess", {})
            if not remote_access:
                return {
                    "has_remote_access": False,
                    "unrestricted": False,
                }
            ec2_ssh_key = remote_access.get("ec2SshKey")
            source_sgs = remote_access.get(
                "sourceSecurityGroups", []
            )
            unrestricted = bool(
                ec2_ssh_key and not source_sgs
            )
            return {
                "has_remote_access": bool(ec2_ssh_key),
                "unrestricted": unrestricted,
                "ec2_ssh_key": ec2_ssh_key,
                "source_security_groups": source_sgs,
            }
        except Exception as e:
            self.logger.warning(
                f"Remote access check failed: {e}"
            )
            return {
                "has_remote_access": True,
                "unrestricted": True,
                "error": str(e),
            }

    def check_disk_encryption(
        self, nodegroup: Dict[str, Any],
        region: str = None,
    ) -> Dict[str, Any]:
        """E.2 - Check disk encryption configuration.

        If the node group uses a launch template, inspect
        the template's BlockDeviceMappings to verify EBS
        Encrypted=true. If no launch template is set, query
        ec2:GetEbsEncryptionByDefault for the region default.
        Falls back to encrypted=False if neither signal can
        be obtained.
        """
        try:
            disk_size = nodegroup.get("diskSize", 20)
            launch_template = nodegroup.get(
                "launchTemplate", {}
            )
            has_template = bool(
                launch_template.get("id")
                or launch_template.get("name")
            )

            if has_template and region:
                try:
                    ec2 = self.get_client("ec2", region)
                    kwargs = {}
                    if launch_template.get("id"):
                        kwargs["LaunchTemplateId"] = (
                            launch_template["id"]
                        )
                    else:
                        kwargs["LaunchTemplateName"] = (
                            launch_template["name"]
                        )
                    if launch_template.get("version"):
                        kwargs["Versions"] = [
                            launch_template["version"]
                        ]
                    resp = (
                        ec2.describe_launch_template_versions(
                            **kwargs
                        )
                    )
                    versions = resp.get(
                        "LaunchTemplateVersions", []
                    )
                    bdm_found = False
                    encrypted = False
                    for v in versions:
                        data = v.get(
                            "LaunchTemplateData", {}
                        )
                        bdms = data.get(
                            "BlockDeviceMappings", []
                        )
                        if not bdms:
                            continue
                        bdm_found = True
                        encrypted = all(
                            bdm.get("Ebs", {}).get(
                                "Encrypted", False
                            )
                            for bdm in bdms
                            if bdm.get("Ebs")
                        )
                        break
                    if bdm_found:
                        return {
                            "disk_size": disk_size,
                            "uses_launch_template": True,
                            "encrypted": encrypted,
                            "source": "launch_template",
                        }
                    # Launch template did not override BDMs.
                    # AMI defaults apply - fall through to
                    # account-level EBS default below.
                except ClientError as e:
                    return self.handle_client_error(e, {
                        "disk_size": disk_size,
                        "uses_launch_template": True,
                        "encrypted": False,
                        "source": "launch_template",
                    })

            # No launch template (or template without BDMs)
            # - check account-level EBS default encryption.
            if region:
                try:
                    ec2 = self.get_client("ec2", region)
                    resp = (
                        ec2.get_ebs_encryption_by_default()
                    )
                    encrypted = resp.get(
                        "EbsEncryptionByDefault", False
                    )
                    return {
                        "disk_size": disk_size,
                        "uses_launch_template": has_template,
                        "encrypted": encrypted,
                        "source": "ebs_default",
                    }
                except ClientError as e:
                    return self.handle_client_error(e, {
                        "disk_size": disk_size,
                        "uses_launch_template": False,
                        "encrypted": False,
                        "source": "ebs_default",
                    })

            return {
                "disk_size": disk_size,
                "uses_launch_template": has_template,
                "encrypted": False,
                "source": "unknown",
            }
        except Exception as e:
            self.logger.warning(
                f"Disk encryption check failed: {e}"
            )
            return {
                "encrypted": False,
                "error": str(e),
            }

    def check_ami_type(
        self, nodegroup: Dict[str, Any]
    ) -> Dict[str, Any]:
        """E.3 - Check amiType against secure list."""
        try:
            ami_type = nodegroup.get("amiType", "")
            is_secure = ami_type in self.SECURE_AMI_TYPES
            return {
                "ami_type": ami_type,
                "is_secure": is_secure,
            }
        except Exception as e:
            self.logger.warning(
                f"AMI type check failed: {e}"
            )
            return {
                "ami_type": "unknown",
                "is_secure": False,
                "error": str(e),
            }

    def check_launch_template(
        self, nodegroup: Dict[str, Any]
    ) -> Dict[str, Any]:
        """E.4 - Check launchTemplate presence."""
        try:
            launch_template = nodegroup.get(
                "launchTemplate", {}
            )
            has_template = bool(
                launch_template.get("id")
                or launch_template.get("name")
            )
            return {
                "has_launch_template": has_template,
                "template_id": launch_template.get("id"),
                "template_name": launch_template.get("name"),
                "template_version": launch_template.get(
                    "version"
                ),
            }
        except Exception as e:
            self.logger.warning(
                f"Launch template check failed: {e}"
            )
            return {
                "has_launch_template": False,
                "template_id": None,
                "template_name": None,
                "template_version": None,
                "error": str(e),
            }

    def check_all(
        self, nodegroup: Dict[str, Any],
        region: str = None,
    ) -> Dict[str, Any]:
        """Run all E.1-E.4 checks on a single EKS node group."""
        return {
            "remote_access": self.check_remote_access(
                nodegroup
            ),
            "disk_encryption": self.check_disk_encryption(
                nodegroup, region
            ),
            "ami_type": self.check_ami_type(nodegroup),
            "launch_template": self.check_launch_template(
                nodegroup
            ),
        }
