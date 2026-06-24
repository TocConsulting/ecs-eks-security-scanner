"""Data Protection Security Checker - H.1-H.4."""

from typing import Dict, Any, List

from botocore.exceptions import ClientError

from .base import BaseChecker


class DataProtectionChecker(BaseChecker):
    """Check data protection configuration.

    H.1 (secrets via Secrets Manager/SSM) is an alias for B.7 -
    evaluated in ECSTaskChecker and shared via the checks dict.
    """

    def check_ecr_scan_on_push(
        self, region: str
    ) -> Dict[str, Any]:
        """H.2 - Check scan-on-push for all ECR repos."""
        try:
            client = self.get_client("ecr", region)
            paginator = client.get_paginator(
                "describe_repositories"
            )
            non_scanning = []
            total = 0

            for page in paginator.paginate():
                for repo in page.get("repositories", []):
                    total += 1
                    scan_config = repo.get(
                        "imageScanningConfiguration", {}
                    )
                    if not scan_config.get(
                        "scanOnPush", False
                    ):
                        non_scanning.append(
                            repo.get("repositoryName", "")
                        )

            if total == 0:
                return {
                    "all_enabled": True,
                    "non_scanning_repos": [],
                    "total_repos": 0,
                }

            return {
                "all_enabled": len(non_scanning) == 0,
                "non_scanning_repos": non_scanning,
                "total_repos": total,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "all_enabled": False,
                "non_scanning_repos": [],
                "total_repos": 0,
            })
        except Exception as e:
            self.logger.warning(
                f"ECR scan-on-push check failed: {e}"
            )
            return {
                "all_enabled": False,
                "non_scanning_repos": [],
                "total_repos": 0,
                "error": str(e),
            }

    def check_ecr_tag_immutability(
        self, region: str
    ) -> Dict[str, Any]:
        """H.3 - Check tag immutability for all ECR repos."""
        try:
            client = self.get_client("ecr", region)
            paginator = client.get_paginator(
                "describe_repositories"
            )
            mutable_repos = []
            total = 0

            for page in paginator.paginate():
                for repo in page.get("repositories", []):
                    total += 1
                    mutability = repo.get(
                        "imageTagMutability", "MUTABLE"
                    )
                    if mutability != "IMMUTABLE":
                        mutable_repos.append(
                            repo.get("repositoryName", "")
                        )

            if total == 0:
                return {
                    "all_immutable": True,
                    "mutable_repos": [],
                    "total_repos": 0,
                }

            return {
                "all_immutable": len(mutable_repos) == 0,
                "mutable_repos": mutable_repos,
                "total_repos": total,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "all_immutable": False,
                "mutable_repos": [],
                "total_repos": 0,
            })
        except Exception as e:
            self.logger.warning(
                f"ECR tag immutability check failed: {e}"
            )
            return {
                "all_immutable": False,
                "mutable_repos": [],
                "total_repos": 0,
                "error": str(e),
            }

    def check_ecr_enhanced_scanning(
        self, region: str
    ) -> Dict[str, Any]:
        """H.2b - Check if ECR Enhanced Scanning is enabled.

        Enhanced Scanning (Amazon Inspector) provides
        continuous CVE coverage for both OS packages and
        language packages (npm, pip, Maven, Go modules).
        It supersedes basic scan-on-push for comprehensive
        vulnerability management.
        """
        try:
            client = self.get_client("ecr", region)
            resp = (
                client.get_registry_scanning_configuration()
            )
            scan_type = resp.get("scanType", "BASIC")
            rules = resp.get("rules", [])
            return {
                "enhanced_enabled": scan_type == "ENHANCED",
                "scan_type": scan_type,
                "rule_count": len(rules),
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "enhanced_enabled": False,
                "scan_type": "UNKNOWN",
                "rule_count": 0,
            })
        except Exception as e:
            self.logger.warning(
                f"ECR enhanced scanning check failed: {e}"
            )
            return {
                "enhanced_enabled": False,
                "scan_type": "UNKNOWN",
                "rule_count": 0,
                "error": str(e),
            }

    def check_in_transit_encryption(
        self, cluster_arn: str, service_type: str,
        region: str
    ) -> Dict[str, Any]:
        """H.4 - Check TLS/in-transit encryption configuration.

        For ECS: checks Service Connect TLS and load balancers
        on services in the cluster.
        For EKS: checks if secrets encryption is configured
        on the cluster.
        """
        try:
            if service_type == "ecs":
                return self._check_ecs_in_transit(
                    cluster_arn, region
                )
            elif service_type == "eks":
                return self._check_eks_in_transit(
                    cluster_arn, region
                )
            return {
                "configured": False,
                "error": f"Unknown service type: "
                         f"{service_type}",
            }
        except Exception as e:
            self.logger.warning(
                f"In-transit encryption check failed: {e}"
            )
            return {
                "configured": False,
                "error": str(e),
            }

    def _check_ecs_in_transit(
        self, cluster_arn: str, region: str
    ) -> Dict[str, Any]:
        """Check ECS services for Service Connect / LB."""
        try:
            ecs = self.get_client("ecs", region)

            svc_arns = []
            paginator = ecs.get_paginator("list_services")
            for page in paginator.paginate(
                cluster=cluster_arn
            ):
                svc_arns.extend(
                    page.get("serviceArns", [])
                )

            if not svc_arns:
                return {
                    "configured": False,
                    "service_connect_enabled": False,
                    "has_load_balancer": False,
                }

            sc_enabled = False
            has_lb = False

            for i in range(0, len(svc_arns), 10):
                batch = svc_arns[i:i + 10]
                try:
                    resp = ecs.describe_services(
                        cluster=cluster_arn,
                        services=batch,
                    )
                    for svc in resp.get("services", []):
                        sc_config = svc.get(
                            "serviceConnectConfiguration",
                            {},
                        )
                        # Service Connect "enabled" alone
                        # doesn't enforce TLS - the per-
                        # service `tls` key with an issuer
                        # CA is what does.
                        # https://docs.aws.amazon.com/
                        #   AmazonECS/latest/APIReference/
                        #   API_ServiceConnectService.html
                        if sc_config.get("enabled", False):
                            sc_services = sc_config.get(
                                "services", []
                            )
                            if sc_services and all(
                                s.get("tls")
                                for s in sc_services
                            ):
                                sc_enabled = True
                        if svc.get("loadBalancers"):
                            has_lb = True
                except ClientError:
                    pass

            return {
                "configured": sc_enabled or has_lb,
                "service_connect_enabled": sc_enabled,
                "has_load_balancer": has_lb,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "configured": False,
                "service_connect_enabled": False,
                "has_load_balancer": False,
            })

    def _check_eks_in_transit(
        self, cluster_arn: str, region: str
    ) -> Dict[str, Any]:
        """Check EKS encryption and private endpoint.

        NOTE: This check is a proxy for in-transit
        protection. It evaluates:
          - secrets encryption (KMS envelope encryption)
          - private endpoint access (forces all traffic
            through the VPC rather than the public internet)

        True TLS in-transit enforcement (network policies,
        service mesh mTLS) is not assessable via the EKS
        API alone. Configured=True when either control is
        active; both should be enabled for full coverage.
        """
        try:
            cluster_name = cluster_arn.split("/")[-1]
            eks = self.get_client("eks", region)
            resp = eks.describe_cluster(name=cluster_name)
            cluster = resp.get("cluster", {})

            # Check encryptionConfig for secrets encryption
            enc_config = cluster.get(
                "encryptionConfig", []
            )
            secrets_encrypted = False
            for ec in enc_config:
                resources = ec.get("resources", [])
                if "secrets" in resources:
                    secrets_encrypted = True

            # Check endpoint private access
            vpc_config = cluster.get(
                "resourcesVpcConfig", {}
            )
            private_access = vpc_config.get(
                "endpointPrivateAccess", False
            )

            return {
                "configured": (
                    secrets_encrypted and private_access
                ),
                "secrets_encrypted": secrets_encrypted,
                "private_endpoint": private_access,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "configured": False,
                "secrets_encrypted": False,
                "private_endpoint": False,
            })
