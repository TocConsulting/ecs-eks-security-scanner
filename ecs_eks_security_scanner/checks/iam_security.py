"""IAM & Access Control Security Checker - F.1-F.5."""

import json
import urllib.parse
from typing import Dict, Any, List

from botocore.exceptions import ClientError

from .base import BaseChecker


class IAMSecurityChecker(BaseChecker):
    """Check IAM security configuration for ECS/EKS."""

    # Exact AWS-managed policy ARNs that grant overly
    # broad permissions. Exact match avoids false positives
    # like AdministratorAccess-Amplify (a scoped variant).
    # Source: https://docs.aws.amazon.com/IAM/latest/
    # UserGuide/access_policies_managed-vs-inline.html
    ADMIN_POLICY_ARNS = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        # Organizations admin in a member account is
        # effectively admin across the org.
        (
            "arn:aws:iam::aws:policy/"
            "AWSOrganizationsFullAccess"
        ),
    }

    # Service-level wildcards that effectively grant admin
    # on a major service.
    DANGEROUS_ACTION_WILDCARDS = [
        "*",
        "iam:*",
        "sts:*",
        "kms:*",
        "s3:*",
        "ec2:*",
    ]

    # --- internal helpers ---

    def _check_role_for_admin(
        self, role_arn: str, region: str
    ) -> Dict[str, Any]:
        """Check a single IAM role for admin/wildcard policies."""
        try:
            if not role_arn:
                return {
                    "has_admin": False,
                    "admin_policies": [],
                    "wildcard_actions": False,
                }
            iam = self.get_client("iam", region)
            role_name = role_arn.split("/")[-1]

            # Check attached managed policies
            admin_policies = []
            try:
                paginator = iam.get_paginator(
                    "list_attached_role_policies"
                )
                for page in paginator.paginate(
                    RoleName=role_name
                ):
                    for policy in page.get(
                        "AttachedPolicies", []
                    ):
                        policy_arn = policy.get(
                            "PolicyArn", ""
                        )
                        if policy_arn in (
                            self.ADMIN_POLICY_ARNS
                        ):
                            admin_policies.append(
                                policy_arn
                            )
            except ClientError:
                pass

            # Check inline policies for wildcard actions
            # or NotAction (which is allow-everything-except)
            wildcard_found = False
            try:
                paginator = iam.get_paginator(
                    "list_role_policies"
                )
                for page in paginator.paginate(
                    RoleName=role_name
                ):
                    for policy_name in page.get(
                        "PolicyNames", []
                    ):
                        try:
                            resp = iam.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name,
                            )
                            doc = resp.get(
                                "PolicyDocument", {}
                            )
                            if isinstance(doc, str):
                                doc = json.loads(
                                    urllib.parse.unquote(
                                        doc
                                    )
                                )
                            for stmt in doc.get(
                                "Statement", []
                            ):
                                if (
                                    stmt.get("Effect")
                                    != "Allow"
                                ):
                                    continue
                                actions = stmt.get(
                                    "Action", []
                                )
                                if isinstance(
                                    actions, str
                                ):
                                    actions = [actions]
                                if any(
                                    a in actions
                                    for a in (
                                        self
                                        .DANGEROUS_ACTION_WILDCARDS
                                    )
                                ):
                                    wildcard_found = True
                                # NotAction with broad
                                # Effect=Allow is the
                                # allow-everything-except
                                # antipattern.
                                if stmt.get("NotAction"):
                                    wildcard_found = True
                        except ClientError:
                            pass
            except ClientError:
                pass

            has_admin = (
                len(admin_policies) > 0 or wildcard_found
            )
            return {
                "has_admin": has_admin,
                "admin_policies": admin_policies,
                "wildcard_actions": wildcard_found,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "has_admin": False,
                "admin_policies": [],
                "wildcard_actions": False,
            })
        except Exception as e:
            self.logger.warning(
                f"Role admin check failed: {e}"
            )
            return {
                "has_admin": False,
                "admin_policies": [],
                "wildcard_actions": False,
                "error": str(e),
            }

    def _get_ecs_task_defs_for_cluster(
        self, cluster_arn: str, region: str
    ) -> List[Dict[str, Any]]:
        """Get task definitions used by services in an ECS cluster."""
        task_defs = []
        try:
            ecs = self.get_client("ecs", region)

            # List services
            svc_arns = []
            paginator = ecs.get_paginator("list_services")
            for page in paginator.paginate(
                cluster=cluster_arn
            ):
                svc_arns.extend(
                    page.get("serviceArns", [])
                )

            if not svc_arns:
                return task_defs

            # Describe services in batches of 10
            td_arns = set()
            for i in range(0, len(svc_arns), 10):
                batch = svc_arns[i:i + 10]
                try:
                    resp = ecs.describe_services(
                        cluster=cluster_arn,
                        services=batch,
                    )
                    for svc in resp.get("services", []):
                        td_arn = svc.get("taskDefinition")
                        if td_arn:
                            td_arns.add(td_arn)
                except ClientError:
                    pass

            # Describe each task definition
            for td_arn in td_arns:
                try:
                    resp = ecs.describe_task_definition(
                        taskDefinition=td_arn
                    )
                    td = resp.get("taskDefinition", {})
                    if td:
                        task_defs.append(td)
                except ClientError:
                    pass

        except ClientError as e:
            self.logger.warning(
                f"Failed to get task defs for cluster: {e}"
            )
        return task_defs

    # --- F.1: Role separation (ECS cluster level) ---

    def check_role_separation(
        self, cluster_arn: str, region: str
    ) -> Dict[str, Any]:
        """F.1 - Check taskRoleArn != executionRoleArn for
        task definitions in an ECS cluster."""
        try:
            task_defs = self._get_ecs_task_defs_for_cluster(
                cluster_arn, region
            )
            if not task_defs:
                return {
                    "separated": True,
                    "violations": [],
                    "task_definitions_checked": 0,
                }

            violations = []
            for td in task_defs:
                task_role = td.get("taskRoleArn", "")
                exec_role = td.get("executionRoleArn", "")
                if task_role and exec_role and task_role == exec_role:
                    violations.append({
                        "task_definition": td.get(
                            "taskDefinitionArn", ""
                        ),
                        "shared_role": task_role,
                    })

            return {
                "separated": len(violations) == 0,
                "violations": violations,
                "task_definitions_checked": len(task_defs),
            }
        except Exception as e:
            self.logger.warning(
                f"Role separation check failed: {e}"
            )
            return {
                "separated": True,
                "violations": [],
                "error": str(e),
            }

    # --- F.2: Overly permissive roles (ECS/EKS) ---

    def check_overly_permissive_roles(
        self, cluster_arn: str, service_type: str,
        region: str
    ) -> Dict[str, Any]:
        """F.2 - Check for admin/wildcard policies on roles
        used by an ECS or EKS cluster."""
        try:
            role_arns = set()

            if service_type == "ecs":
                task_defs = (
                    self._get_ecs_task_defs_for_cluster(
                        cluster_arn, region
                    )
                )
                for td in task_defs:
                    for key in (
                        "taskRoleArn", "executionRoleArn"
                    ):
                        arn = td.get(key, "")
                        if arn:
                            role_arns.add(arn)
            elif service_type == "eks":
                # For EKS, check node group roles
                try:
                    eks = self.get_client("eks", region)
                    cluster_name = cluster_arn.split("/")[-1]
                    ng_paginator = eks.get_paginator(
                        "list_nodegroups"
                    )
                    for page in ng_paginator.paginate(
                        clusterName=cluster_name
                    ):
                        for ng_name in page.get(
                            "nodegroups", []
                        ):
                            try:
                                ng_resp = (
                                    eks.describe_nodegroup(
                                        clusterName=cluster_name,
                                        nodegroupName=ng_name,
                                    )
                                )
                                ng_role = ng_resp.get(
                                    "nodegroup", {}
                                ).get("nodeRole", "")
                                if ng_role:
                                    role_arns.add(ng_role)
                            except ClientError:
                                pass
                except ClientError:
                    pass

            admin_roles = []
            for role_arn in role_arns:
                result = self._check_role_for_admin(
                    role_arn, region
                )
                if result.get("has_admin"):
                    admin_roles.append({
                        "role_arn": role_arn,
                        "admin_policies": result.get(
                            "admin_policies", []
                        ),
                        "wildcard_actions": result.get(
                            "wildcard_actions", False
                        ),
                    })

            return {
                "has_admin_roles": len(admin_roles) > 0,
                "admin_role_arns": admin_roles,
                "overly_permissive": len(admin_roles) > 0,
                "roles_checked": len(role_arns),
            }
        except Exception as e:
            self.logger.warning(
                f"Overly permissive roles check failed: {e}"
            )
            return {
                "has_admin_roles": False,
                "admin_role_arns": [],
                "overly_permissive": False,
                "error": str(e),
            }

    # --- F.3: OIDC provider (EKS) ---

    def check_oidc_provider(
        self, cluster: Dict[str, Any], region: str
    ) -> Dict[str, Any]:
        """F.3 - Check OIDC issuer and IAM provider."""
        try:
            identity = cluster.get("identity", {})
            oidc = identity.get("oidc", {})
            issuer_url = oidc.get("issuer", "")

            if not issuer_url:
                return {
                    "configured": False,
                    "issuer_url": None,
                }

            # Check if IAM OIDC provider exists
            iam = self.get_client("iam", region)
            try:
                providers = (
                    iam.list_open_id_connect_providers()
                )
                provider_arns = [
                    p["Arn"]
                    for p in providers.get(
                        "OpenIDConnectProviderList", []
                    )
                ]
                # Match issuer URL to provider
                issuer_host = issuer_url.replace(
                    "https://", ""
                )
                has_provider = any(
                    issuer_host in arn
                    for arn in provider_arns
                )
            except ClientError:
                has_provider = False

            return {
                "configured": has_provider,
                "issuer_url": issuer_url,
                "has_iam_provider": has_provider,
            }
        except Exception as e:
            self.logger.warning(
                f"OIDC provider check failed: {e}"
            )
            return {
                "configured": False,
                "issuer_url": None,
                "error": str(e),
            }

    # --- F.4: Execution policy on task role (ECS) ---

    def check_execution_policy_on_task(
        self, cluster_arn: str, region: str
    ) -> Dict[str, Any]:
        """F.4 - Task role should not have execution policies.
        Checks all task definitions in the ECS cluster."""
        try:
            task_defs = self._get_ecs_task_defs_for_cluster(
                cluster_arn, region
            )
            if not task_defs:
                return {
                    "has_violation": False,
                    "violations": [],
                }

            execution_policies = [
                "AmazonECSTaskExecutionRolePolicy",
                "AmazonEC2ContainerRegistryReadOnly",
            ]

            iam = self.get_client("iam", region)
            violations = []

            for td in task_defs:
                task_role = td.get("taskRoleArn", "")
                if not task_role:
                    continue
                role_name = task_role.split("/")[-1]
                try:
                    paginator = iam.get_paginator(
                        "list_attached_role_policies"
                    )
                    for page in paginator.paginate(
                        RoleName=role_name
                    ):
                        for policy in page.get(
                            "AttachedPolicies", []
                        ):
                            name = policy.get(
                                "PolicyName", ""
                            )
                            if name in execution_policies:
                                violations.append({
                                    "task_definition": td.get(
                                        "taskDefinitionArn",
                                        "",
                                    ),
                                    "task_role": task_role,
                                    "policy": name,
                                })
                except ClientError:
                    pass

            return {
                "has_violation": len(violations) > 0,
                "violations": violations,
            }
        except Exception as e:
            self.logger.warning(
                f"Execution policy check failed: {e}"
            )
            return {
                "has_violation": False,
                "violations": [],
                "error": str(e),
            }

    # --- F.5: Cluster role permissions (EKS) ---

    def check_cluster_role_permissions(
        self, cluster: Dict[str, Any], region: str
    ) -> Dict[str, Any]:
        """F.5 - Check EKS cluster IAM role for overly
        permissive policies."""
        try:
            role_arn = cluster.get("roleArn", "")
            if not role_arn:
                return {
                    "has_admin": False,
                    "overly_permissive": False,
                    "role_arn": None,
                }

            result = self._check_role_for_admin(
                role_arn, region
            )
            return {
                "has_admin": result.get("has_admin", False),
                "overly_permissive": result.get(
                    "has_admin", False
                ),
                "role_arn": role_arn,
                "admin_policies": result.get(
                    "admin_policies", []
                ),
                "wildcard_actions": result.get(
                    "wildcard_actions", False
                ),
            }
        except Exception as e:
            self.logger.warning(
                f"Cluster role permissions check failed: {e}"
            )
            return {
                "has_admin": False,
                "overly_permissive": False,
                "role_arn": cluster.get("roleArn", ""),
                "error": str(e),
            }
