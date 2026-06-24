"""EKS Cluster Security Checker - D.1-D.8."""

from typing import Dict, Any, List

from botocore.exceptions import ClientError

from .base import BaseChecker


class EKSClusterChecker(BaseChecker):
    """Check EKS cluster-level security configuration."""

    REQUIRED_LOG_TYPES = [
        "api", "audit", "authenticator",
        "controllerManager", "scheduler",
    ]
    REQUIRED_ADDONS = [
        "vpc-cni", "kube-proxy", "coredns",
    ]
    # EKS support tiers as of 2026-05-17.
    # Standard support: 1.33-1.35.
    # Extended support (paid, still supported): 1.30-1.32.
    # Versions below 1.30 are EOL.
    # Sources:
    #  - https://endoflife.date/amazon-eks
    #  - https://docs.aws.amazon.com/eks/latest/userguide/
    #    kubernetes-versions.html
    # Keep this list updated with each EKS release; AWS
    # bumped oldestVersionSupported to 1.33 on 2026-04-03.
    SUPPORTED_VERSIONS = [
        "1.35", "1.34", "1.33", "1.32", "1.31", "1.30",
    ]
    STANDARD_SUPPORT_VERSIONS = [
        "1.35", "1.34", "1.33",
    ]

    def check_endpoint_public_access(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """D.1 - Check endpointPublicAccess and CIDRs.

        When public access is disabled, AWS still returns
        the saved publicAccessCidrs list (often
        ["0.0.0.0/0"]). Surface an empty list in that case
        so downstream UI doesn't confuse users into thinking
        the cluster is reachable from anywhere.
        """
        try:
            vpc_config = cluster.get(
                "resourcesVpcConfig", {}
            )
            public_access = vpc_config.get(
                "endpointPublicAccess", True
            )
            raw_cidrs = vpc_config.get(
                "publicAccessCidrs", ["0.0.0.0/0"]
            )
            unrestricted = (
                public_access
                and "0.0.0.0/0" in raw_cidrs
            )
            public_cidrs = raw_cidrs if public_access else []
            return {
                "public": public_access,
                "unrestricted": unrestricted,
                "public_cidrs": public_cidrs,
            }
        except Exception as e:
            self.logger.warning(
                f"Endpoint public access check failed: {e}"
            )
            return {
                "public": True,
                "unrestricted": True,
                "public_cidrs": ["0.0.0.0/0"],
                "error": str(e),
            }

    def check_endpoint_private_access(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """D.2 - Check endpointPrivateAccess."""
        try:
            vpc_config = cluster.get(
                "resourcesVpcConfig", {}
            )
            private_access = vpc_config.get(
                "endpointPrivateAccess", False
            )
            return {"enabled": private_access}
        except Exception as e:
            self.logger.warning(
                f"Endpoint private access check failed: {e}"
            )
            return {"enabled": False, "error": str(e)}

    def check_secrets_encryption(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """D.3 - Check encryptionConfig for secrets."""
        try:
            encryption_config = cluster.get(
                "encryptionConfig", []
            )
            kms_key_arn = None
            enabled = False
            for config in encryption_config:
                resources = config.get("resources", [])
                if "secrets" in resources:
                    enabled = True
                    provider = config.get("provider", {})
                    kms_key_arn = provider.get("keyArn")
                    break
            return {
                "enabled": enabled,
                "kms_key_arn": kms_key_arn,
            }
        except Exception as e:
            self.logger.warning(
                f"Secrets encryption check failed: {e}"
            )
            return {
                "enabled": False,
                "kms_key_arn": None,
                "error": str(e),
            }

    def check_control_plane_logging(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """D.4 - Check all 5 control plane log types."""
        try:
            logging_config = cluster.get("logging", {})
            cluster_logging = logging_config.get(
                "clusterLogging", []
            )
            enabled_types = []
            for entry in cluster_logging:
                if entry.get("enabled", False):
                    enabled_types.extend(
                        entry.get("types", [])
                    )
            missing_types = [
                t for t in self.REQUIRED_LOG_TYPES
                if t not in enabled_types
            ]
            return {
                "all_enabled": len(missing_types) == 0,
                "enabled_types": enabled_types,
                "missing_types": missing_types,
            }
        except Exception as e:
            self.logger.warning(
                f"Control plane logging check failed: {e}"
            )
            return {
                "all_enabled": False,
                "enabled_types": [],
                "missing_types": list(self.REQUIRED_LOG_TYPES),
                "error": str(e),
            }

    def check_kubernetes_version(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """D.5 - Check Kubernetes version against supported.

        Distinguishes EOL versions (no longer supported by
        AWS at any tier) from extended-support versions
        (still supported but paid). Both report
        supported=False so existing scoring still triggers,
        but a separate flag lets the consumer differentiate.
        """
        try:
            version = cluster.get("version", "")
            in_standard = version in (
                self.STANDARD_SUPPORT_VERSIONS
            )
            in_extended = (
                version in self.SUPPORTED_VERSIONS
                and not in_standard
            )
            is_supported = in_standard
            is_eol = version not in self.SUPPORTED_VERSIONS
            return {
                "supported": is_supported,
                "version": version,
                "is_eol": is_eol,
                "extended_support": in_extended,
            }
        except Exception as e:
            self.logger.warning(
                f"Kubernetes version check failed: {e}"
            )
            return {
                "supported": False,
                "version": "unknown",
                "is_eol": True,
                "extended_support": False,
                "error": str(e),
            }

    def check_cluster_security_group(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """D.6 - Check clusterSecurityGroupId."""
        try:
            vpc_config = cluster.get(
                "resourcesVpcConfig", {}
            )
            sg_id = vpc_config.get("clusterSecurityGroupId")
            return {
                "configured": bool(sg_id),
                "security_group_id": sg_id,
            }
        except Exception as e:
            self.logger.warning(
                f"Cluster security group check failed: {e}"
            )
            return {
                "configured": False,
                "security_group_id": None,
                "error": str(e),
            }

    def check_managed_addons(
        self, cluster_name: str, region: str
    ) -> Dict[str, Any]:
        """D.7 - Check required add-ons are installed."""
        try:
            client = self.get_client("eks", region)
            paginator = client.get_paginator("list_addons")
            installed = []
            for page in paginator.paginate(
                clusterName=cluster_name
            ):
                installed.extend(page.get("addons", []))
            missing = [
                a for a in self.REQUIRED_ADDONS
                if a not in installed
            ]
            return {
                "all_present": len(missing) == 0,
                "installed_addons": installed,
                "missing_addons": missing,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "all_present": False,
                "installed_addons": [],
                "missing_addons": list(self.REQUIRED_ADDONS),
            })
        except Exception as e:
            self.logger.warning(
                f"Managed addons check failed: {e}"
            )
            return {
                "all_present": False,
                "installed_addons": [],
                "missing_addons": list(self.REQUIRED_ADDONS),
                "error": str(e),
            }

    def check_fargate_profiles(
        self, cluster_name: str, region: str
    ) -> Dict[str, Any]:
        """D.8 - Check Fargate profile subnet configuration.

        Verifies Fargate profiles use private subnets by
        calling ec2:DescribeSubnets. If that permission is
        unavailable, marks the subnet check as skipped
        rather than silently passing.
        """
        try:
            client = self.get_client("eks", region)
            paginator = client.get_paginator(
                "list_fargate_profiles"
            )
            profile_names = []
            for page in paginator.paginate(
                clusterName=cluster_name
            ):
                profile_names.extend(
                    page.get("fargateProfileNames", [])
                )
            if not profile_names:
                return {
                    "has_profiles": False,
                    "profile_count": 0,
                    "private_subnets_only": True,
                }

            # Collect all subnet IDs across profiles
            all_subnet_ids: List[str] = []
            for name in profile_names:
                try:
                    resp = client.describe_fargate_profile(
                        clusterName=cluster_name,
                        fargateProfileName=name,
                    )
                    profile = resp.get("fargateProfile", {})
                    subnets = profile.get("subnets", [])
                    all_subnet_ids.extend(subnets)
                except Exception:
                    pass

            if not all_subnet_ids:
                # No subnets configured means Fargate picks
                # private subnets automatically - safe.
                return {
                    "has_profiles": True,
                    "profile_count": len(profile_names),
                    "private_subnets_only": True,
                }

            # Verify subnets are private via ec2:DescribeSubnets
            private_only = True
            try:
                ec2 = self.get_client("ec2", region)
                unique_subnets = list(set(all_subnet_ids))
                sub_resp = ec2.describe_subnets(
                    SubnetIds=unique_subnets
                )
                for sub in sub_resp.get("Subnets", []):
                    if sub.get("MapPublicIpOnLaunch", False):
                        private_only = False
                        break
            except ClientError as ec2_err:
                error_code = ec2_err.response.get(
                    "Error", {}
                ).get("Code", "")
                # Any ClientError leaves the subnet privacy
                # status unknown - flag as skipped rather
                # than silently passing. Differentiate
                # AccessDenied for cleaner ops messages.
                if error_code in (
                    "AccessDenied",
                    "UnauthorizedOperation",
                ):
                    self.logger.warning(
                        "ec2:DescribeSubnets permission "
                        "missing - Fargate subnet privacy "
                        "check skipped"
                    )
                else:
                    self.logger.warning(
                        "ec2:DescribeSubnets %s - Fargate "
                        "subnet privacy check skipped",
                        error_code or str(ec2_err),
                    )
                return {
                    "has_profiles": True,
                    "profile_count": len(profile_names),
                    "private_subnets_only": True,
                    "subnet_check_skipped": True,
                }

            return {
                "has_profiles": True,
                "profile_count": len(profile_names),
                "private_subnets_only": private_only,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "has_profiles": False,
                "profile_count": 0,
                "private_subnets_only": True,
            })
        except Exception as e:
            self.logger.warning(
                f"Fargate profiles check failed: {e}"
            )
            return {
                "has_profiles": False,
                "profile_count": 0,
                "private_subnets_only": True,
                "error": str(e),
            }
