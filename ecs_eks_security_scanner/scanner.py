#!/usr/bin/env python3
"""ECS/EKS Security Scanner - Main orchestrator with
multi-threading, compliance mapping, and dual-service
scanning architecture."""

import csv
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .compliance import ComplianceChecker
from .html_reporter import HTMLReporter
from .utils import (
    setup_logging,
    calculate_ecs_security_score,
    calculate_eks_security_score,
    score_to_color,
)
from .checks.ecs_cluster import ECSClusterChecker
from .checks.ecs_task import ECSTaskChecker
from .checks.ecs_service import ECSServiceChecker
from .checks.eks_cluster import EKSClusterChecker
from .checks.eks_nodegroup import EKSNodeGroupChecker
from .checks.iam_security import IAMSecurityChecker
from .checks.logging_monitoring import LoggingMonitoringChecker
from .checks.data_protection import DataProtectionChecker


class ContainerSecurityScanner:
    """ECS/EKS Security Scanner driving all checks.

    Facade pattern: orchestrates scanning across 8 checker
    modules, manages thread pool, progress display, and
    report generation for both ECS and EKS clusters.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        output_dir: str = "./output",
        max_workers: int = 5,
    ):
        """Initialize the Container Security Scanner.

        Args:
            region: AWS region for API calls
            profile: AWS profile name
            output_dir: Directory for reports and logs
            max_workers: Maximum parallel threads
        """
        self.region = region
        self.profile = profile
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.console = Console()

        os.makedirs(output_dir, exist_ok=True)
        self.logger = setup_logging(output_dir)

        # Thread safety
        self._thread_local = threading.local()

        # ECR cache (account-level, computed once)
        self._ecr_cache = None
        self._ecr_cache_lock = threading.Lock()

        # Setup AWS session for main thread
        try:
            self._session = self._create_session()
            self.account_id = self._get_account_id()
        except NoCredentialsError:
            self.logger.error(
                "No AWS credentials found. "
                "Please configure your credentials."
            )
            raise

        # ECS checkers
        self.ecs_cluster_checker = ECSClusterChecker(
            self._get_thread_session
        )
        self.ecs_task_checker = ECSTaskChecker(
            self._get_thread_session
        )
        self.ecs_service_checker = ECSServiceChecker(
            self._get_thread_session
        )

        # EKS checkers
        self.eks_cluster_checker = EKSClusterChecker(
            self._get_thread_session
        )
        self.eks_nodegroup_checker = EKSNodeGroupChecker(
            self._get_thread_session
        )

        # Shared checkers
        self.iam_checker = IAMSecurityChecker(
            self._get_thread_session
        )
        self.logging_checker = LoggingMonitoringChecker(
            self._get_thread_session
        )
        self.data_checker = DataProtectionChecker(
            self._get_thread_session
        )

        # Compliance & reporting
        self.compliance_checker = ComplianceChecker()
        self.html_reporter = HTMLReporter()

    # ============================================================
    # Session Management
    # ============================================================

    def _create_session(self) -> boto3.Session:
        """Create a boto3 session with profile if specified."""
        if self.profile:
            return boto3.Session(
                profile_name=self.profile,
                region_name=self.region,
            )
        return boto3.Session(region_name=self.region)

    def _get_thread_session(self) -> boto3.Session:
        """Get or create a session for the current thread.

        Thread-local storage ensures each thread gets its
        own boto3 session, avoiding cross-thread issues.
        """
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = (
                self._create_session()
            )
        return self._thread_local.session

    def _get_account_id(self) -> str:
        """Get the AWS account ID via STS."""
        try:
            sts = self._session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as e:
            self.logger.debug(
                "Could not determine AWS account ID: "
                f"{e}"
            )
            return "unknown"

    # ============================================================
    # Cluster Enumeration
    # ============================================================

    def get_ecs_clusters(self) -> List[Dict[str, Any]]:
        """Retrieve all ECS clusters using pagination.

        Uses paginated list_clusters followed by
        describe_clusters in batches of up to 100.

        Returns:
            List of cluster dicts from describe_clusters
        """
        try:
            ecs = self._session.client(
                "ecs", region_name=self.region
            )
            paginator = ecs.get_paginator("list_clusters")

            cluster_arns = []
            for page in paginator.paginate():
                cluster_arns.extend(
                    page.get("clusterArns", [])
                )

            if not cluster_arns:
                self.logger.info(
                    "No ECS clusters found in "
                    f"{self.region}"
                )
                return []

            # Describe in batches of 100 (API limit)
            clusters = []
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i:i + 100]
                resp = ecs.describe_clusters(
                    clusters=batch,
                    include=[
                        "SETTINGS",
                        "CONFIGURATIONS",
                        "ATTACHMENTS",
                    ],
                )
                clusters.extend(
                    resp.get("clusters", [])
                )

            self.logger.info(
                f"Found {len(clusters)} ECS clusters "
                f"in {self.region}"
            )
            return clusters

        except Exception as e:
            self.logger.error(
                f"Error retrieving ECS clusters: {e}"
            )
            return []

    def get_eks_clusters(self) -> List[Dict[str, Any]]:
        """Retrieve all EKS clusters using pagination.

        Uses paginated list_clusters followed by
        describe_cluster for each cluster individually.

        Returns:
            List of cluster dicts from describe_cluster
        """
        try:
            eks = self._session.client(
                "eks", region_name=self.region
            )
            paginator = eks.get_paginator("list_clusters")

            cluster_names = []
            for page in paginator.paginate():
                cluster_names.extend(
                    page.get("clusters", [])
                )

            if not cluster_names:
                self.logger.info(
                    "No EKS clusters found in "
                    f"{self.region}"
                )
                return []

            # Describe one at a time (API constraint)
            clusters = []
            for name in cluster_names:
                try:
                    resp = eks.describe_cluster(
                        name=name
                    )
                    clusters.append(
                        resp.get("cluster", {})
                    )
                except ClientError as e:
                    self.logger.warning(
                        f"Could not describe EKS "
                        f"cluster {name}: {e}"
                    )

            self.logger.info(
                f"Found {len(clusters)} EKS clusters "
                f"in {self.region}"
            )
            return clusters

        except Exception as e:
            self.logger.error(
                f"Error retrieving EKS clusters: {e}"
            )
            return []

    # ============================================================
    # ECR Caching (account-level, H.2 and H.3)
    # ============================================================

    def _get_ecr_results(self) -> Dict[str, Any]:
        """Get cached ECR scan results (thread-safe).

        H.2 (scan on push), H.2b (enhanced scanning) and
        H.3 (tag immutability) are account-level checks.
        We cache them inside the lock to prevent TOCTOU
        races where multiple threads all see cache as None
        and redundantly compute ECR results.
        """
        with self._ecr_cache_lock:
            if self._ecr_cache is not None:
                return self._ecr_cache

            ecr_scan = (
                self.data_checker.check_ecr_scan_on_push(
                    self.region
                )
            )
            ecr_enhanced = (
                self.data_checker
                .check_ecr_enhanced_scanning(self.region)
            )
            ecr_tags = (
                self.data_checker
                .check_ecr_tag_immutability(self.region)
            )

            self._ecr_cache = {
                "ecr_scan_on_push": ecr_scan,
                "ecr_enhanced_scanning": ecr_enhanced,
                "ecr_tag_immutability": ecr_tags,
            }
            return self._ecr_cache

    # ============================================================
    # ECS Cluster Scanning
    # ============================================================

    def scan_ecs_cluster(
        self, cluster_arn: str,
    ) -> Dict[str, Any]:
        """Scan a single ECS cluster with all checks.

        Runs A.1-A.5 (cluster), B.1-B.10 (task defs),
        C.1-C.5 (services), F.1/F.2/F.4 (IAM),
        G.3/G.4 (monitoring), H.2-H.4 (data protection).

        Args:
            cluster_arn: Full ARN of the ECS cluster

        Returns:
            Complete result dict per Section 6.1
        """
        cluster_name = cluster_arn.split("/")[-1]

        try:
            ecs = self._get_thread_session().client(
                "ecs", region_name=self.region
            )

            # Describe the cluster
            desc_resp = ecs.describe_clusters(
                clusters=[cluster_arn],
                include=[
                    "SETTINGS",
                    "CONFIGURATIONS",
                    "ATTACHMENTS",
                ],
            )
            cluster_list = desc_resp.get("clusters", [])
            if not cluster_list:
                return self._error_result(
                    cluster_name, "ecs",
                    f"Cluster {cluster_arn} not found",
                )
            cluster = cluster_list[0]

            result = {
                "cluster_name": cluster_name,
                "cluster_arn": cluster_arn,
                "cluster_type": "ecs",
                "region": self.region,
                "account_id": self.account_id,
                "scan_timestamp": (
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                ),
                "status": cluster.get("status", ""),
            }

            # === A. ECS Cluster Configuration ===
            result["container_insights"] = (
                self.ecs_cluster_checker
                .check_container_insights(cluster)
            )
            result["execute_command_logging"] = (
                self.ecs_cluster_checker
                .check_execute_command_logging(cluster)
            )
            result["cluster_encryption"] = (
                self.ecs_cluster_checker
                .check_cluster_encryption(cluster)
            )
            result["capacity_provider_strategy"] = (
                self.ecs_cluster_checker
                .check_capacity_provider_strategy(cluster)
            )
            result["service_connect_namespace"] = (
                self.ecs_cluster_checker
                .check_service_connect_namespace(cluster)
            )

            # === List services (paginated) ===
            svc_paginator = ecs.get_paginator(
                "list_services"
            )
            service_arns = []
            for page in svc_paginator.paginate(
                cluster=cluster_arn
            ):
                service_arns.extend(
                    page.get("serviceArns", [])
                )

            service_count = len(service_arns)
            result["service_count"] = service_count

            if service_count > 0:
                # Describe services in batches of 10
                services = []
                for i in range(
                    0, len(service_arns), 10
                ):
                    batch = service_arns[i:i + 10]
                    svc_resp = ecs.describe_services(
                        cluster=cluster_arn,
                        services=batch,
                        include=["TAGS"],
                    )
                    services.extend(
                        svc_resp.get("services", [])
                    )

                # === C. Service Security ===
                svc_results = []
                for svc in services:
                    svc_checks = (
                        self.ecs_service_checker
                        .check_all(svc)
                    )
                    svc_results.append(svc_checks)

                # Aggregate service results
                result.update(
                    self._aggregate_service_results(
                        svc_results, services
                    )
                )

                # === B. Task Definition Security ===
                task_def_arns = set()
                for svc in services:
                    td_arn = svc.get("taskDefinition")
                    if td_arn:
                        task_def_arns.add(td_arn)

                td_results = []
                for td_arn in task_def_arns:
                    try:
                        td_resp = (
                            ecs.describe_task_definition(
                                taskDefinition=td_arn,
                                include=["TAGS"],
                            )
                        )
                        td = td_resp.get(
                            "taskDefinition", {}
                        )
                        td_checks = (
                            self.ecs_task_checker
                            .check_all(td)
                        )
                        td_results.append(td_checks)
                    except ClientError as e:
                        self.logger.warning(
                            "Could not describe task "
                            f"definition {td_arn}: {e}"
                        )

                result["task_definition_count"] = len(
                    task_def_arns
                )

                # Aggregate task definition results
                result.update(
                    self._aggregate_task_def_results(
                        td_results, list(task_def_arns)
                    )
                )

            else:
                # Zero-services handling
                result["task_definition_count"] = 0
                result.update(
                    self._zero_services_defaults()
                )

            # === F. IAM (ECS-relevant) ===
            result["role_separation"] = (
                self.iam_checker
                .check_role_separation(
                    cluster_arn, self.region
                )
            )
            result["overly_permissive_roles"] = (
                self.iam_checker
                .check_overly_permissive_roles(
                    cluster_arn, "ecs", self.region
                )
            )
            result["execution_policy_on_task"] = (
                self.iam_checker
                .check_execution_policy_on_task(
                    cluster_arn, self.region
                )
            )

            # === G. Logging & Monitoring ===
            result["guardduty_enabled"] = (
                self.logging_checker
                .check_guardduty_ecs(self.region)
            )
            result["vpc_flow_logs"] = (
                self.logging_checker
                .check_vpc_flow_logs(
                    cluster_arn, self.region
                )
            )

            # === H. Data Protection ===
            ecr_results = self._get_ecr_results()
            result["ecr_scan_on_push"] = (
                ecr_results["ecr_scan_on_push"]
            )
            result["ecr_enhanced_scanning"] = (
                ecr_results["ecr_enhanced_scanning"]
            )
            result["ecr_tag_immutability"] = (
                ecr_results["ecr_tag_immutability"]
            )
            result["in_transit_encryption"] = (
                self.data_checker
                .check_in_transit_encryption(
                    cluster_arn, "ecs", self.region
                )
            )

            # === Computed fields ===
            result["issues"] = (
                self._analyze_ecs_issues(result)
            )
            result["issue_count"] = len(
                result["issues"]
            )
            result["has_critical_severity"] = any(
                i["severity"] == "CRITICAL"
                for i in result["issues"]
            )
            result["has_high_severity"] = any(
                i["severity"] == "HIGH"
                for i in result["issues"]
            )
            result["security_score"] = (
                calculate_ecs_security_score(result)
            )
            result["compliance_status"] = (
                self.compliance_checker
                .check_cluster_compliance(
                    result, "ecs"
                )
            )
            result["scan_error"] = False

            return result

        except Exception as e:
            self.logger.error(
                f"Error scanning ECS cluster "
                f"{cluster_name}: {e}"
            )
            return self._error_result(
                cluster_name, "ecs", str(e)
            )

    def _aggregate_service_results(
        self,
        svc_results: List[Dict],
        services: List[Dict],
    ) -> Dict[str, Any]:
        """Aggregate C.1-C.5 across all services."""
        svc_names = [
            s.get("serviceName", s.get("serviceArn", ""))
            for s in services
        ]

        # C.1 ECS Exec enabled
        exec_svcs = [
            svc_names[i]
            for i, r in enumerate(svc_results)
            if r.get("ecs_exec", {}).get(
                "enabled", False
            )
        ]
        # C.2 Public IP assignment
        pub_svcs = [
            svc_names[i]
            for i, r in enumerate(svc_results)
            if r.get("public_ip", {}).get(
                "assigns_public_ip", False
            )
        ]
        # C.3 Circuit breaker
        no_cb_svcs = [
            svc_names[i]
            for i, r in enumerate(svc_results)
            if not r.get("circuit_breaker", {}).get(
                "enabled", False
            )
        ]
        # C.4 Fargate platform version
        outdated_svcs = [
            svc_names[i]
            for i, r in enumerate(svc_results)
            if not r.get(
                "fargate_platform_version", {}
            ).get("is_latest", True)
        ]
        # C.5 Security groups
        no_sg_svcs = [
            svc_names[i]
            for i, r in enumerate(svc_results)
            if not r.get("security_groups", {}).get(
                "has_security_groups", True
            )
        ]

        return {
            "ecs_exec_enabled": {
                "any_enabled": len(exec_svcs) > 0,
                "services": exec_svcs,
            },
            "public_ip_assignment": {
                "any_public": len(pub_svcs) > 0,
                "services": pub_svcs,
            },
            "circuit_breaker": {
                "all_enabled": len(no_cb_svcs) == 0,
                "missing_services": no_cb_svcs,
            },
            "fargate_platform_version": {
                "all_latest": len(outdated_svcs) == 0,
                "outdated_services": outdated_svcs,
            },
            "service_security_groups": {
                "all_configured": (
                    len(no_sg_svcs) == 0
                ),
                "missing_sg_services": no_sg_svcs,
            },
        }

    def _aggregate_task_def_results(
        self,
        td_results: List[Dict],
        td_arns: List[str],
    ) -> Dict[str, Any]:
        """Aggregate B.1-B.10 across all task defs."""
        priv_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if r.get("privileged", {}).get(
                "has_privileged", False
            )
        ]
        root_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if r.get("root_user", {}).get(
                "has_root_user", False
            )
        ]
        non_ro_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if not r.get("readonly_root_fs", {}).get(
                "all_readonly", True
            )
        ]
        cap_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if r.get("linux_capabilities", {}).get(
                "has_dangerous_caps", False
            )
        ]
        all_caps = []
        for r in td_results:
            all_caps.extend(
                r.get("linux_capabilities", {}).get(
                    "dangerous_caps_found", []
                )
            )
        non_vpc_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if not r.get("network_mode", {}).get(
                "is_awsvpc", True
            )
        ]
        unlogged_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if not r.get("logging", {}).get(
                "all_configured", True
            )
        ]
        secret_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if r.get("secrets_in_env", {}).get(
                "has_plaintext_secrets", False
            )
        ]
        all_findings = []
        for r in td_results:
            all_findings.extend(
                r.get("secrets_in_env", {}).get(
                    "findings", []
                )
            )
        no_limits_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if not r.get("resource_limits", {}).get(
                "all_defined", True
            )
        ]
        host_pid_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if r.get("pid_mode", {}).get(
                "has_host_pid", False
            )
        ]
        no_exec_tds = [
            td_arns[i]
            for i, r in enumerate(td_results)
            if not r.get("execution_role", {}).get(
                "has_execution_role", True
            )
        ]

        return {
            "privileged_containers": {
                "has_privileged": len(priv_tds) > 0,
                "task_definitions": priv_tds,
            },
            "root_user_containers": {
                "has_root_user": len(root_tds) > 0,
                "task_definitions": root_tds,
            },
            "readonly_root_fs": {
                "all_readonly": len(non_ro_tds) == 0,
                "task_definitions": non_ro_tds,
            },
            "linux_capabilities": {
                "has_dangerous_caps": (
                    len(cap_tds) > 0
                ),
                "dangerous_caps_found": list(
                    set(all_caps)
                ),
                "task_definitions": cap_tds,
            },
            "network_mode": {
                "all_awsvpc": (
                    len(non_vpc_tds) == 0
                ),
                "non_awsvpc_tasks": non_vpc_tds,
            },
            "container_logging": {
                "all_configured": (
                    len(unlogged_tds) == 0
                ),
                "unlogged_tasks": unlogged_tds,
            },
            "secrets_in_env": {
                "has_plaintext_secrets": (
                    len(secret_tds) > 0
                ),
                "findings": all_findings,
                "task_definitions": secret_tds,
            },
            "resource_limits": {
                "all_defined": (
                    len(no_limits_tds) == 0
                ),
                "missing_limits_tasks": no_limits_tds,
            },
            "pid_mode": {
                "has_host_pid": (
                    len(host_pid_tds) > 0
                ),
                "task_definitions": host_pid_tds,
            },
            "execution_role": {
                "all_configured": (
                    len(no_exec_tds) == 0
                ),
                "missing_role_tasks": no_exec_tds,
            },
        }

    def _zero_services_defaults(
        self,
    ) -> Dict[str, Any]:
        """Safe defaults for B.* and C.* keys when a
        cluster has zero services or task definitions."""
        return {
            "privileged_containers": {
                "has_privileged": False,
                "task_definitions": [],
            },
            "root_user_containers": {
                "has_root_user": False,
                "task_definitions": [],
            },
            "readonly_root_fs": {
                "all_readonly": True,
                "task_definitions": [],
            },
            "linux_capabilities": {
                "has_dangerous_caps": False,
                "dangerous_caps_found": [],
                "task_definitions": [],
            },
            "network_mode": {
                "all_awsvpc": True,
                "non_awsvpc_tasks": [],
            },
            "container_logging": {
                "all_configured": True,
                "unlogged_tasks": [],
            },
            "secrets_in_env": {
                "has_plaintext_secrets": False,
                "findings": [],
                "task_definitions": [],
            },
            "resource_limits": {
                "all_defined": True,
                "missing_limits_tasks": [],
            },
            "pid_mode": {
                "has_host_pid": False,
                "task_definitions": [],
            },
            "execution_role": {
                "all_configured": True,
                "missing_role_tasks": [],
            },
            "ecs_exec_enabled": {
                "any_enabled": False,
                "services": [],
            },
            "public_ip_assignment": {
                "any_public": False,
                "services": [],
            },
            "circuit_breaker": {
                "all_enabled": True,
                "missing_services": [],
            },
            "fargate_platform_version": {
                "all_latest": True,
                "outdated_services": [],
            },
            "service_security_groups": {
                "all_configured": True,
                "missing_sg_services": [],
            },
        }

    # ============================================================
    # EKS Cluster Scanning
    # ============================================================

    def scan_eks_cluster(
        self, cluster_name: str,
    ) -> Dict[str, Any]:
        """Scan a single EKS cluster with all checks.

        Runs D.1-D.8 (cluster), E.1-E.4 (node groups),
        F.3/F.5 (IAM), G.3/G.4 (monitoring),
        H.2-H.4 (data protection).

        Args:
            cluster_name: Name of the EKS cluster

        Returns:
            Complete result dict per Section 6.2
        """
        try:
            eks = self._get_thread_session().client(
                "eks", region_name=self.region
            )

            # Describe the cluster
            desc_resp = eks.describe_cluster(
                name=cluster_name
            )
            cluster = desc_resp.get("cluster", {})

            result = {
                "cluster_name": cluster_name,
                "cluster_arn": cluster.get("arn", ""),
                "cluster_type": "eks",
                "region": self.region,
                "account_id": self.account_id,
                "scan_timestamp": (
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                ),
                "status": cluster.get("status", ""),
                "kubernetes_version": cluster.get(
                    "version", ""
                ),
                "platform_version": cluster.get(
                    "platformVersion", ""
                ),
            }

            # === D. EKS Cluster Configuration ===
            result["endpoint_public_access"] = (
                self.eks_cluster_checker
                .check_endpoint_public_access(cluster)
            )
            result["endpoint_private_access"] = (
                self.eks_cluster_checker
                .check_endpoint_private_access(cluster)
            )
            result["secrets_encryption"] = (
                self.eks_cluster_checker
                .check_secrets_encryption(cluster)
            )
            result["control_plane_logging"] = (
                self.eks_cluster_checker
                .check_control_plane_logging(cluster)
            )
            result["kubernetes_version_check"] = (
                self.eks_cluster_checker
                .check_kubernetes_version(cluster)
            )
            result["cluster_security_group"] = (
                self.eks_cluster_checker
                .check_cluster_security_group(cluster)
            )
            result["managed_addons"] = (
                self.eks_cluster_checker
                .check_managed_addons(
                    cluster_name, self.region
                )
            )
            result["fargate_profiles"] = (
                self.eks_cluster_checker
                .check_fargate_profiles(
                    cluster_name, self.region
                )
            )

            # === E. Node Group Security ===
            ng_paginator = eks.get_paginator(
                "list_nodegroups"
            )
            nodegroup_names = []
            for page in ng_paginator.paginate(
                clusterName=cluster_name
            ):
                nodegroup_names.extend(
                    page.get("nodegroups", [])
                )

            result["nodegroup_count"] = len(
                nodegroup_names
            )

            if nodegroup_names:
                ng_results = []
                for ng_name in nodegroup_names:
                    try:
                        ng_resp = (
                            eks.describe_nodegroup(
                                clusterName=cluster_name,
                                nodegroupName=ng_name,
                            )
                        )
                        ng = ng_resp.get(
                            "nodegroup", {}
                        )
                        ng_checks = (
                            self.eks_nodegroup_checker
                            .check_all(ng, self.region)
                        )
                        ng_results.append(ng_checks)
                    except ClientError as e:
                        self.logger.warning(
                            "Could not describe node "
                            f"group {ng_name}: {e}"
                        )

                result.update(
                    self._aggregate_nodegroup_results(
                        ng_results, nodegroup_names
                    )
                )
            else:
                result.update(
                    self._zero_nodegroups_defaults()
                )

            # === F. IAM (EKS-relevant) ===
            result["oidc_provider"] = (
                self.iam_checker
                .check_oidc_provider(
                    cluster, self.region
                )
            )
            result["cluster_role_permissions"] = (
                self.iam_checker
                .check_cluster_role_permissions(
                    cluster, self.region
                )
            )
            result["overly_permissive_roles"] = (
                self.iam_checker
                .check_overly_permissive_roles(
                    cluster.get("arn", ""),
                    "eks",
                    self.region,
                )
            )

            # === G. Logging & Monitoring ===
            result["guardduty_enabled"] = (
                self.logging_checker
                .check_guardduty_eks(self.region)
            )
            result["vpc_flow_logs"] = (
                self.logging_checker
                .check_vpc_flow_logs(
                    cluster.get("arn", ""),
                    self.region,
                )
            )

            # === H. Data Protection ===
            ecr_results = self._get_ecr_results()
            result["ecr_scan_on_push"] = (
                ecr_results["ecr_scan_on_push"]
            )
            result["ecr_enhanced_scanning"] = (
                ecr_results["ecr_enhanced_scanning"]
            )
            result["ecr_tag_immutability"] = (
                ecr_results["ecr_tag_immutability"]
            )
            result["in_transit_encryption"] = (
                self.data_checker
                .check_in_transit_encryption(
                    cluster.get("arn", ""),
                    "eks",
                    self.region,
                )
            )

            # === Computed fields ===
            result["issues"] = (
                self._analyze_eks_issues(result)
            )
            result["issue_count"] = len(
                result["issues"]
            )
            result["has_critical_severity"] = any(
                i["severity"] == "CRITICAL"
                for i in result["issues"]
            )
            result["has_high_severity"] = any(
                i["severity"] == "HIGH"
                for i in result["issues"]
            )
            result["security_score"] = (
                calculate_eks_security_score(result)
            )
            result["compliance_status"] = (
                self.compliance_checker
                .check_cluster_compliance(
                    result, "eks"
                )
            )
            result["scan_error"] = False

            return result

        except Exception as e:
            self.logger.error(
                f"Error scanning EKS cluster "
                f"{cluster_name}: {e}"
            )
            return self._error_result(
                cluster_name, "eks", str(e)
            )

    def _aggregate_nodegroup_results(
        self,
        ng_results: List[Dict],
        ng_names: List[str],
    ) -> Dict[str, Any]:
        """Aggregate E.1-E.4 across all node groups.

        Per-nodegroup results come from EKSNodeGroupChecker.check_all
        as nested dicts. Read the nested keys directly.
        """
        unrestricted_ngs = [
            ng_names[i]
            for i, r in enumerate(ng_results)
            if r.get("remote_access", {}).get(
                "unrestricted", False
            )
        ]
        unencrypted_ngs = [
            ng_names[i]
            for i, r in enumerate(ng_results)
            if not r.get("disk_encryption", {}).get(
                "encrypted", True
            )
        ]
        insecure_ngs = [
            ng_names[i]
            for i, r in enumerate(ng_results)
            if not r.get("ami_type", {}).get(
                "is_secure", True
            )
        ]
        no_template_ngs = [
            ng_names[i]
            for i, r in enumerate(ng_results)
            if not r.get("launch_template", {}).get(
                "has_launch_template", True
            )
        ]

        return {
            "nodegroup_remote_access": {
                "any_unrestricted": (
                    len(unrestricted_ngs) > 0
                ),
                "unrestricted_nodegroups": (
                    unrestricted_ngs
                ),
            },
            "nodegroup_disk_encryption": {
                "all_encrypted": (
                    len(unencrypted_ngs) == 0
                ),
                "unencrypted_nodegroups": (
                    unencrypted_ngs
                ),
            },
            "nodegroup_ami_type": {
                "all_secure": (
                    len(insecure_ngs) == 0
                ),
                "insecure_nodegroups": insecure_ngs,
            },
            "nodegroup_launch_template": {
                "all_use_template": (
                    len(no_template_ngs) == 0
                ),
                "no_template_nodegroups": (
                    no_template_ngs
                ),
            },
        }

    def _zero_nodegroups_defaults(
        self,
    ) -> Dict[str, Any]:
        """Safe defaults for E.* keys when a cluster has
        zero node groups."""
        return {
            "nodegroup_remote_access": {
                "any_unrestricted": False,
                "unrestricted_nodegroups": [],
            },
            "nodegroup_disk_encryption": {
                "all_encrypted": True,
                "unencrypted_nodegroups": [],
            },
            "nodegroup_ami_type": {
                "all_secure": True,
                "insecure_nodegroups": [],
            },
            "nodegroup_launch_template": {
                "all_use_template": True,
                "no_template_nodegroups": [],
            },
        }

    # ============================================================
    # Parallel Scanning
    # ============================================================

    def scan_all_clusters(
        self,
        service: str = "all",
        ecs_clusters: Optional[List[Dict]] = None,
        eks_clusters: Optional[List[Dict]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan all clusters in parallel with progress.

        Args:
            service: "ecs", "eks", or "all"
            ecs_clusters: Pre-filtered ECS cluster list
                (skips enumeration if provided)
            eks_clusters: Pre-filtered EKS cluster list
                (skips enumeration if provided)

        Returns:
            List of result dicts sorted by security_score
            ascending (worst first)
        """
        if ecs_clusters is None:
            ecs_clusters = []
            if service in ("ecs", "all"):
                ecs_clusters = self.get_ecs_clusters()
        if eks_clusters is None:
            eks_clusters = []
            if service in ("eks", "all"):
                eks_clusters = self.get_eks_clusters()

        total = len(ecs_clusters) + len(eks_clusters)

        if total == 0:
            self.logger.warning(
                "No clusters found to scan"
            )
            return []

        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn(
                "[progress.description]"
                "{task.description}"
            ),
            console=self.console,
        ) as progress:
            task = progress.add_task(
                f"Scanning {total} clusters...",
                total=total,
            )

            with ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as executor:
                future_to_cluster = {}

                # Submit ECS scans
                for cluster in ecs_clusters:
                    arn = cluster.get(
                        "clusterArn", ""
                    )
                    future = executor.submit(
                        self.scan_ecs_cluster, arn
                    )
                    future_to_cluster[future] = (
                        arn, "ecs"
                    )

                # Submit EKS scans
                for cluster in eks_clusters:
                    name = cluster.get("name", "")
                    future = executor.submit(
                        self.scan_eks_cluster, name
                    )
                    future_to_cluster[future] = (
                        name, "eks"
                    )

                for future in as_completed(
                    future_to_cluster
                ):
                    cid, ctype = (
                        future_to_cluster[future]
                    )
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        self.logger.error(
                            f"Scan failed for "
                            f"{ctype} {cid}: {e}"
                        )
                        name = (
                            cid.split("/")[-1]
                            if "/" in cid
                            else cid
                        )
                        results.append(
                            self._error_result(
                                name, ctype, str(e)
                            )
                        )
                    progress.advance(task)

        # Sort by security score ascending (worst first)
        results.sort(
            key=lambda r: (
                r.get("security_score")
                if r.get("security_score") is not None
                else 101
            )
        )

        return results

    # ============================================================
    # Issue Analysis
    # ============================================================

    def _analyze_ecs_issues(
        self, checks: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate issue list for an ECS cluster."""
        issues = []

        def add(
            severity, issue_type,
            description, recommendation,
        ):
            issues.append({
                "severity": severity,
                "issue_type": issue_type,
                "description": description,
                "recommendation": recommendation,
            })

        # A.1 Container Insights
        ci = checks.get("container_insights", {})
        if not ci.get("enabled", False):
            add(
                "MEDIUM",
                "CONTAINER_INSIGHTS_DISABLED",
                "Container Insights is not enabled "
                "on the ECS cluster.",
                "Enable Container Insights for "
                "monitoring and performance metrics",
            )

        # A.2 Execute Command Logging
        ecl = checks.get(
            "execute_command_logging", {}
        )
        if not ecl.get("configured", False):
            add(
                "HIGH",
                "EXECUTE_COMMAND_LOGGING_DISABLED",
                "ECS Exec logging is not configured. "
                "Interactive sessions are unaudited.",
                "Configure execute command logging "
                "with CloudWatch or S3",
            )

        # A.3 Cluster Encryption
        ce = checks.get("cluster_encryption", {})
        if not ce.get("kms_enabled", False):
            add(
                "MEDIUM",
                "CLUSTER_ENCRYPTION_DISABLED",
                "Cluster managed storage is not "
                "encrypted with KMS.",
                "Enable KMS encryption for ECS "
                "managed storage",
            )

        # A.4 Capacity Provider Strategy
        cps = checks.get(
            "capacity_provider_strategy", {}
        )
        if not cps.get("has_strategy", False):
            add(
                "LOW",
                "NO_CAPACITY_PROVIDER_STRATEGY",
                "No capacity provider strategy "
                "configured.",
                "Configure a capacity provider "
                "strategy for managed scaling",
            )

        # A.5 Service Connect Namespace
        scn = checks.get(
            "service_connect_namespace", {}
        )
        if not scn.get("configured", False):
            add(
                "LOW",
                "NO_SERVICE_CONNECT_NAMESPACE",
                "Service Connect namespace is not "
                "configured.",
                "Configure Service Connect for "
                "service mesh capabilities",
            )

        # B.1 Privileged Containers
        pc = checks.get(
            "privileged_containers", {}
        )
        if pc.get("has_privileged", False):
            tds = pc.get("task_definitions", [])
            add(
                "CRITICAL",
                "PRIVILEGED_CONTAINERS",
                f"Privileged containers found in "
                f"{len(tds)} task definition(s).",
                "Remove privileged flag from "
                "container definitions",
            )

        # B.2 Root User
        ru = checks.get("root_user_containers", {})
        if ru.get("has_root_user", False):
            tds = ru.get("task_definitions", [])
            add(
                "HIGH",
                "ROOT_USER_CONTAINERS",
                f"Containers running as root in "
                f"{len(tds)} task definition(s).",
                "Set user to non-root in container "
                "definitions",
            )

        # B.3 Read-only Root Filesystem
        ro = checks.get("readonly_root_fs", {})
        if not ro.get("all_readonly", True):
            tds = ro.get("task_definitions", [])
            add(
                "HIGH",
                "WRITABLE_ROOT_FILESYSTEM",
                f"Writable root filesystem in "
                f"{len(tds)} task definition(s).",
                "Enable readonlyRootFilesystem in "
                "container definitions",
            )

        # B.4 Linux Capabilities
        lc = checks.get("linux_capabilities", {})
        if lc.get("has_dangerous_caps", False):
            caps = lc.get(
                "dangerous_caps_found", []
            )
            add(
                "HIGH",
                "DANGEROUS_LINUX_CAPABILITIES",
                "Dangerous Linux capabilities "
                f"found: {caps}",
                "Drop all capabilities and add only "
                "those strictly required",
            )

        # B.5 Network Mode
        nm = checks.get("network_mode", {})
        if not nm.get("all_awsvpc", True):
            tds = nm.get("non_awsvpc_tasks", [])
            add(
                "HIGH",
                "NON_AWSVPC_NETWORK_MODE",
                f"Non-awsvpc network mode in "
                f"{len(tds)} task definition(s).",
                "Use awsvpc network mode for task "
                "level security group enforcement",
            )

        # B.6 Container Logging
        cl = checks.get("container_logging", {})
        if not cl.get("all_configured", True):
            tds = cl.get("unlogged_tasks", [])
            add(
                "HIGH",
                "CONTAINER_LOGGING_MISSING",
                f"No logging configured in "
                f"{len(tds)} task definition(s).",
                "Configure logConfiguration in all "
                "container definitions",
            )

        # B.7 Secrets in Environment Variables
        se = checks.get("secrets_in_env", {})
        if se.get("has_plaintext_secrets", False):
            tds = se.get("task_definitions", [])
            add(
                "CRITICAL",
                "SECRETS_IN_ENVIRONMENT",
                f"Plaintext secrets in environment "
                f"variables in {len(tds)} task "
                f"definition(s).",
                "Use AWS Secrets Manager or SSM "
                "Parameter Store for secrets",
            )

        # B.8 Resource Limits
        rl = checks.get("resource_limits", {})
        if not rl.get("all_defined", True):
            tds = rl.get("missing_limits_tasks", [])
            add(
                "MEDIUM",
                "MISSING_RESOURCE_LIMITS",
                f"No resource limits in "
                f"{len(tds)} task definition(s).",
                "Define cpu and memory limits in "
                "container definitions",
            )

        # B.9 PID Mode
        pm = checks.get("pid_mode", {})
        if pm.get("has_host_pid", False):
            tds = pm.get("task_definitions", [])
            add(
                "HIGH",
                "HOST_PID_MODE",
                f"Host PID namespace shared in "
                f"{len(tds)} task definition(s).",
                "Remove pidMode=host from task "
                "definitions",
            )

        # B.10 Execution Role
        er = checks.get("execution_role", {})
        if not er.get("all_configured", True):
            tds = er.get("missing_role_tasks", [])
            add(
                "HIGH",
                "MISSING_EXECUTION_ROLE",
                f"No execution role in "
                f"{len(tds)} task definition(s).",
                "Assign an execution role to all "
                "task definitions",
            )

        # C.1 ECS Exec Enabled
        ee = checks.get("ecs_exec_enabled", {})
        if ee.get("any_enabled", False):
            svcs = ee.get("services", [])
            add(
                "MEDIUM",
                "ECS_EXEC_ENABLED",
                f"ECS Exec enabled on "
                f"{len(svcs)} service(s).",
                "Disable ECS Exec when not "
                "needed for debugging",
            )

        # C.2 Public IP Assignment
        pip = checks.get(
            "public_ip_assignment", {}
        )
        if pip.get("any_public", False):
            svcs = pip.get("services", [])
            add(
                "HIGH",
                "PUBLIC_IP_ASSIGNED",
                f"Public IP assigned to "
                f"{len(svcs)} service(s).",
                "Use private subnets with NAT "
                "gateway or VPC endpoints",
            )

        # C.3 Circuit Breaker
        cb = checks.get("circuit_breaker", {})
        if not cb.get("all_enabled", True):
            svcs = cb.get("missing_services", [])
            add(
                "MEDIUM",
                "CIRCUIT_BREAKER_DISABLED",
                f"Circuit breaker not enabled on "
                f"{len(svcs)} service(s).",
                "Enable deployment circuit breaker "
                "with rollback",
            )

        # C.4 Fargate Platform Version
        fpv = checks.get(
            "fargate_platform_version", {}
        )
        if not fpv.get("all_latest", True):
            svcs = fpv.get("outdated_services", [])
            add(
                "MEDIUM",
                "OUTDATED_FARGATE_PLATFORM",
                f"Outdated Fargate platform in "
                f"{len(svcs)} service(s).",
                "Update to LATEST Fargate platform "
                "version",
            )

        # C.5 Service Security Groups
        ssg = checks.get(
            "service_security_groups", {}
        )
        if not ssg.get("all_configured", True):
            svcs = ssg.get(
                "missing_sg_services", []
            )
            add(
                "HIGH",
                "MISSING_SERVICE_SECURITY_GROUPS",
                f"No security groups on "
                f"{len(svcs)} service(s).",
                "Configure security groups for "
                "all services using awsvpc mode",
            )

        # F.1 Role Separation
        rs = checks.get("role_separation", {})
        if not rs.get("separated", True):
            add(
                "HIGH",
                "NO_ROLE_SEPARATION",
                "Task role and execution role are "
                "not separated.",
                "Use distinct IAM roles for task "
                "execution and task roles",
            )

        # F.2 Overly Permissive Roles
        opr = checks.get(
            "overly_permissive_roles", {}
        )
        if opr.get("has_admin_roles", False):
            arns = opr.get("admin_role_arns", [])
            add(
                "CRITICAL",
                "OVERLY_PERMISSIVE_ROLES",
                f"Admin/wildcard roles found: "
                f"{len(arns)} role(s).",
                "Apply least privilege to all "
                "ECS task and execution roles",
            )

        # F.4 Execution Policy on Task Role
        epot = checks.get(
            "execution_policy_on_task", {}
        )
        if epot.get("has_violation", False):
            add(
                "HIGH",
                "EXECUTION_POLICY_ON_TASK",
                "Execution-level policies attached "
                "to task role.",
                "Separate execution and task role "
                "permissions",
            )

        # G.3 GuardDuty
        gd = checks.get("guardduty_enabled", {})
        if not gd.get("enabled", False):
            add(
                "HIGH",
                "GUARDDUTY_DISABLED",
                "GuardDuty is not enabled.",
                "Enable GuardDuty with ECS runtime "
                "monitoring",
            )
        elif not gd.get(
            "ecs_runtime_monitoring", False
        ):
            add(
                "MEDIUM",
                "GUARDDUTY_ECS_RUNTIME_DISABLED",
                "GuardDuty ECS Runtime Monitoring "
                "is not enabled.",
                "Enable ECS Runtime Monitoring in "
                "GuardDuty",
            )

        # G.4 VPC Flow Logs
        vfl = checks.get("vpc_flow_logs", {})
        if not vfl.get("enabled", False):
            add(
                "MEDIUM",
                "NO_VPC_FLOW_LOGS",
                "VPC flow logging is not enabled.",
                "Enable VPC flow logs for network "
                "traffic analysis",
            )

        # H.2 ECR Scan on Push
        esp = checks.get("ecr_scan_on_push", {})
        if not esp.get("all_enabled", True):
            repos = esp.get(
                "non_scanning_repos", []
            )
            add(
                "HIGH",
                "ECR_SCAN_ON_PUSH_DISABLED",
                f"Scan on push disabled for "
                f"{len(repos)} ECR repo(s).",
                "Enable scan on push for all "
                "ECR repositories",
            )

        # H.2b ECR Enhanced Scanning
        ees = checks.get(
            "ecr_enhanced_scanning", {}
        )
        if not ees.get("enhanced_enabled", False):
            add(
                "MEDIUM",
                "ECR_ENHANCED_SCANNING_DISABLED",
                "ECR Enhanced Scanning (Amazon "
                "Inspector) is not enabled. Only "
                "basic OS scanning is active.",
                "Enable Enhanced Scanning in ECR "
                "registry settings for continuous "
                "CVE coverage including language "
                "packages",
            )

        # H.3 ECR Tag Immutability
        eti = checks.get(
            "ecr_tag_immutability", {}
        )
        if not eti.get("all_immutable", True):
            repos = eti.get("mutable_repos", [])
            add(
                "MEDIUM",
                "ECR_TAG_MUTABLE",
                f"Mutable tags on "
                f"{len(repos)} ECR repo(s).",
                "Enable tag immutability on all "
                "ECR repositories",
            )

        # H.4 In-transit Encryption
        ite = checks.get(
            "in_transit_encryption", {}
        )
        if not ite.get("configured", False):
            add(
                "HIGH",
                "IN_TRANSIT_ENCRYPTION_MISSING",
                "In-transit encryption is not "
                "configured.",
                "Configure TLS for service-to-"
                "service communication",
            )

        return issues

    def _analyze_eks_issues(
        self, checks: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate issue list for an EKS cluster."""
        issues = []

        def add(
            severity, issue_type,
            description, recommendation,
        ):
            issues.append({
                "severity": severity,
                "issue_type": issue_type,
                "description": description,
                "recommendation": recommendation,
            })

        # D.1 Endpoint Public Access
        epa = checks.get(
            "endpoint_public_access", {}
        )
        if epa.get("public", False):
            if epa.get("unrestricted", False):
                add(
                    "CRITICAL",
                    "EKS_PUBLIC_ENDPOINT_UNRESTRICTED",
                    "EKS API endpoint is public and "
                    "unrestricted (0.0.0.0/0).",
                    "Restrict public access CIDRs "
                    "or disable public endpoint",
                )
            else:
                add(
                    "MEDIUM",
                    "EKS_PUBLIC_ENDPOINT",
                    "EKS API endpoint is publicly "
                    "accessible.",
                    "Consider disabling public "
                    "endpoint if not required",
                )

        # D.2 Endpoint Private Access
        epra = checks.get(
            "endpoint_private_access", {}
        )
        if not epra.get("enabled", False):
            add(
                "HIGH",
                "EKS_PRIVATE_ENDPOINT_DISABLED",
                "Private endpoint access is not "
                "enabled.",
                "Enable private endpoint access "
                "for cluster API server",
            )

        # D.3 Secrets Encryption
        se = checks.get("secrets_encryption", {})
        if not se.get("enabled", False):
            add(
                "HIGH",
                "EKS_SECRETS_NOT_ENCRYPTED",
                "Kubernetes secrets are not "
                "encrypted with KMS.",
                "Enable envelope encryption for "
                "Kubernetes secrets",
            )

        # D.4 Control Plane Logging
        cpl = checks.get(
            "control_plane_logging", {}
        )
        if not cpl.get("all_enabled", False):
            missing = cpl.get("missing_types", [])
            add(
                "HIGH",
                "CONTROL_PLANE_LOGGING_INCOMPLETE",
                "Not all control plane log types "
                f"enabled. Missing: {missing}",
                "Enable all control plane log "
                "types: api, audit, authenticator, "
                "controllerManager, scheduler",
            )

        # D.5 Kubernetes Version
        kv = checks.get(
            "kubernetes_version_check", {}
        )
        if kv.get("is_eol", False):
            ver = kv.get("version", "")
            add(
                "CRITICAL",
                "KUBERNETES_VERSION_EOL",
                f"Kubernetes version {ver} is "
                f"end-of-life.",
                "Upgrade to a supported "
                "Kubernetes version",
            )
        elif kv.get("extended_support", False):
            ver = kv.get("version", "")
            add(
                "HIGH",
                "KUBERNETES_VERSION_EXTENDED_SUPPORT",
                f"Kubernetes version {ver} is on "
                f"paid EKS extended support.",
                "Upgrade to a standard-support "
                "Kubernetes version to avoid "
                "extended support charges",
            )
        elif not kv.get("supported", True):
            ver = kv.get("version", "")
            add(
                "HIGH",
                "KUBERNETES_VERSION_OUTDATED",
                f"Kubernetes version {ver} is "
                f"outdated.",
                "Upgrade to the latest supported "
                "Kubernetes version",
            )

        # D.6 Cluster Security Group
        csg = checks.get(
            "cluster_security_group", {}
        )
        if not csg.get("configured", True):
            add(
                "MEDIUM",
                "NO_CLUSTER_SECURITY_GROUP",
                "No cluster security group "
                "configured.",
                "Ensure cluster has a properly "
                "configured security group",
            )

        # D.7 Managed Add-ons (LOW: self-managed
        # addons are also supported - this finding
        # recommends managed addons for easier patching)
        ma = checks.get("managed_addons", {})
        if not ma.get("all_present", True):
            missing = ma.get("missing_addons", [])
            add(
                "LOW",
                "MISSING_MANAGED_ADDONS",
                "Recommended EKS add-ons not "
                f"installed as managed: {missing}. "
                "Self-managed equivalents may be "
                "present.",
                "Consider switching to managed "
                "add-ons for automatic version "
                "updates and easier patching",
            )

        # D.8 Fargate Profiles
        fp = checks.get("fargate_profiles", {})
        if fp.get("has_profiles", False):
            if not fp.get(
                "private_subnets_only", True
            ):
                add(
                    "MEDIUM",
                    "FARGATE_PUBLIC_SUBNETS",
                    "Fargate profiles use public "
                    "subnets.",
                    "Configure Fargate profiles "
                    "to use private subnets only",
                )

        # E.1 Node Group Remote Access
        ngra = checks.get(
            "nodegroup_remote_access", {}
        )
        if ngra.get("any_unrestricted", False):
            ngs = ngra.get(
                "unrestricted_nodegroups", []
            )
            add(
                "HIGH",
                "NODEGROUP_REMOTE_ACCESS_OPEN",
                f"Unrestricted SSH access on "
                f"{len(ngs)} node group(s).",
                "Restrict remote access with "
                "source security groups",
            )

        # E.2 Node Group Disk Encryption
        ngde = checks.get(
            "nodegroup_disk_encryption", {}
        )
        if not ngde.get("all_encrypted", True):
            ngs = ngde.get(
                "unencrypted_nodegroups", []
            )
            add(
                "HIGH",
                "NODEGROUP_DISK_NOT_ENCRYPTED",
                f"Unencrypted disks in "
                f"{len(ngs)} node group(s).",
                "Enable disk encryption in "
                "node group launch templates",
            )

        # E.3 Node Group AMI Type
        ngat = checks.get(
            "nodegroup_ami_type", {}
        )
        if not ngat.get("all_secure", True):
            ngs = ngat.get(
                "insecure_nodegroups", []
            )
            add(
                "MEDIUM",
                "NODEGROUP_INSECURE_AMI",
                f"Non-recommended AMI type in "
                f"{len(ngs)} node group(s).",
                "Use Amazon Linux 2 or Bottlerocket "
                "AMIs for node groups",
            )

        # E.4 Node Group Launch Template
        nglt = checks.get(
            "nodegroup_launch_template", {}
        )
        if not nglt.get("all_use_template", True):
            ngs = nglt.get(
                "no_template_nodegroups", []
            )
            add(
                "LOW",
                "NODEGROUP_NO_LAUNCH_TEMPLATE",
                f"No launch template in "
                f"{len(ngs)} node group(s).",
                "Use launch templates for "
                "consistent node configuration",
            )

        # F.3 OIDC Provider
        oidc = checks.get("oidc_provider", {})
        if not oidc.get("configured", False):
            add(
                "HIGH",
                "NO_OIDC_PROVIDER",
                "OIDC provider is not configured "
                "for IRSA.",
                "Create an OIDC provider for "
                "IAM Roles for Service Accounts",
            )

        # F.5 Cluster Role Permissions
        crp = checks.get(
            "cluster_role_permissions", {}
        )
        if crp.get("overly_permissive", False):
            add(
                "HIGH",
                "CLUSTER_ROLE_OVERLY_PERMISSIVE",
                "EKS cluster role has overly "
                "permissive policies.",
                "Apply least privilege to the "
                "EKS cluster IAM role",
            )

        # F.2 Overly Permissive Roles
        opr = checks.get(
            "overly_permissive_roles", {}
        )
        if opr.get("has_admin_roles", False):
            arns = opr.get("admin_role_arns", [])
            add(
                "CRITICAL",
                "OVERLY_PERMISSIVE_ROLES",
                f"Admin/wildcard roles found: "
                f"{len(arns)} role(s).",
                "Apply least privilege to all "
                "EKS-related IAM roles",
            )

        # G.3 GuardDuty
        gd = checks.get("guardduty_enabled", {})
        if not gd.get("enabled", False):
            add(
                "HIGH",
                "GUARDDUTY_DISABLED",
                "GuardDuty is not enabled.",
                "Enable GuardDuty with EKS audit "
                "and runtime monitoring",
            )
        else:
            if not gd.get(
                "eks_audit_monitoring", False
            ):
                add(
                    "MEDIUM",
                    "GUARDDUTY_EKS_AUDIT_DISABLED",
                    "GuardDuty EKS Audit Log "
                    "Monitoring is not enabled.",
                    "Enable EKS Audit Log "
                    "Monitoring in GuardDuty",
                )
            if not gd.get(
                "eks_runtime_monitoring", False
            ):
                add(
                    "MEDIUM",
                    "GUARDDUTY_EKS_RUNTIME_DISABLED",
                    "GuardDuty EKS Runtime "
                    "Monitoring is not enabled.",
                    "Enable EKS Runtime Monitoring "
                    "in GuardDuty",
                )

        # G.4 VPC Flow Logs
        vfl = checks.get("vpc_flow_logs", {})
        if not vfl.get("enabled", False):
            add(
                "MEDIUM",
                "NO_VPC_FLOW_LOGS",
                "VPC flow logging is not enabled.",
                "Enable VPC flow logs for network "
                "traffic analysis",
            )

        # H.2 ECR Scan on Push
        esp = checks.get("ecr_scan_on_push", {})
        if not esp.get("all_enabled", True):
            repos = esp.get(
                "non_scanning_repos", []
            )
            add(
                "HIGH",
                "ECR_SCAN_ON_PUSH_DISABLED",
                f"Scan on push disabled for "
                f"{len(repos)} ECR repo(s).",
                "Enable scan on push for all "
                "ECR repositories",
            )

        # H.2b ECR Enhanced Scanning
        ees = checks.get(
            "ecr_enhanced_scanning", {}
        )
        if not ees.get("enhanced_enabled", False):
            add(
                "MEDIUM",
                "ECR_ENHANCED_SCANNING_DISABLED",
                "ECR Enhanced Scanning (Amazon "
                "Inspector) is not enabled. Only "
                "basic OS scanning is active.",
                "Enable Enhanced Scanning in ECR "
                "registry settings for continuous "
                "CVE coverage including language "
                "packages",
            )

        # H.3 ECR Tag Immutability
        eti = checks.get(
            "ecr_tag_immutability", {}
        )
        if not eti.get("all_immutable", True):
            repos = eti.get("mutable_repos", [])
            add(
                "MEDIUM",
                "ECR_TAG_MUTABLE",
                f"Mutable tags on "
                f"{len(repos)} ECR repo(s).",
                "Enable tag immutability on all "
                "ECR repositories",
            )

        # H.4 In-transit Encryption
        ite = checks.get(
            "in_transit_encryption", {}
        )
        if not ite.get("configured", False):
            add(
                "HIGH",
                "IN_TRANSIT_ENCRYPTION_MISSING",
                "In-transit encryption is not "
                "configured.",
                "Configure TLS for service-to-"
                "service communication",
            )

        return issues

    # ============================================================
    # Error Result
    # ============================================================

    def _error_result(
        self,
        cluster_name: str,
        cluster_type: str,
        error_msg: str,
    ) -> Dict[str, Any]:
        """Generate safe error result dict for a failed
        cluster scan."""
        return {
            "cluster_name": cluster_name,
            "cluster_type": cluster_type,
            "region": self.region,
            "scan_error": True,
            "error_message": error_msg,
            "security_score": None,
            "compliance_status": {},
            "issues": [{
                "severity": "ERROR",
                "issue_type": "SCAN_ERROR",
                "description": error_msg,
                "recommendation": (
                    "Check permissions and retry"
                ),
            }],
            "issue_count": 1,
            "has_critical_severity": False,
            "has_high_severity": False,
        }

    # ============================================================
    # Report Generation
    # ============================================================

    def generate_reports(
        self,
        results: List[Dict[str, Any]],
        output_format: str = "all",
    ) -> Dict[str, str]:
        """Generate reports in requested format(s).

        Returns dict of {format_name: file_path}.
        """
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        report_files = {}

        summary = self._build_summary(results)

        if output_format in ("json", "all"):
            path = self._export_json(
                results, summary, timestamp
            )
            report_files["json"] = path

        if output_format in ("csv", "all"):
            path = self._export_csv(
                results, timestamp
            )
            report_files["csv"] = path

        if output_format in ("html", "all"):
            path = self._export_html(
                results, summary, timestamp
            )
            report_files["html"] = path

        # Always generate compliance report
        path = self._export_compliance(
            results, timestamp
        )
        report_files["compliance"] = path

        return report_files

    def _build_summary(
        self, results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build summary statistics from scan results."""
        valid = [
            r for r in results
            if not r.get("scan_error", False)
        ]
        scores = [
            r["security_score"]
            for r in valid
            if r.get("security_score") is not None
        ]

        return {
            "scan_time": datetime.now().isoformat(),
            "region": self.region,
            "account_id": self.account_id,
            "total_clusters": len(results),
            "ecs_clusters": sum(
                1 for r in results
                if r.get("cluster_type") == "ecs"
            ),
            "eks_clusters": sum(
                1 for r in results
                if r.get("cluster_type") == "eks"
            ),
            "error_clusters": (
                len(results) - len(valid)
            ),
            "critical_severity_clusters": sum(
                1 for r in valid
                if r.get(
                    "has_critical_severity", False
                )
            ),
            "high_severity_clusters": sum(
                1 for r in valid
                if r.get(
                    "has_high_severity", False
                )
            ),
            "average_security_score": (
                round(
                    sum(scores) / len(scores), 1
                )
                if scores
                else 0
            ),
        }

    def _export_json(
        self,
        results: List[Dict],
        summary: Dict,
        timestamp: str,
    ) -> str:
        """Export results as JSON."""
        path = os.path.join(
            self.output_dir,
            f"container_scan_{self.region}"
            f"_{timestamp}.json",
        )
        with open(path, "w") as f:
            json.dump(
                {
                    "summary": summary,
                    "results": results,
                },
                f,
                indent=2,
                default=str,
            )
        return path

    def _export_csv(
        self,
        results: List[Dict],
        timestamp: str,
    ) -> str:
        """Export results as CSV."""
        path = os.path.join(
            self.output_dir,
            f"container_scan_{self.region}"
            f"_{timestamp}.csv",
        )

        fieldnames = [
            "cluster_name",
            "cluster_type",
            "region",
            "status",
            "security_score",
            "issue_count",
            "critical_issues",
            "high_issues",
            "container_insights",
            "data_encryption",
            "privileged_containers",
            "secrets_in_env",
            "guardduty_enabled",
            "vpc_flow_logs",
            "ecr_scan_on_push",
            "in_transit_encryption",
        ]

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()

            for r in results:
                if r.get("scan_error"):
                    continue

                ctype = r.get("cluster_type", "")
                row = {
                    "cluster_name": r.get(
                        "cluster_name"
                    ),
                    "cluster_type": ctype,
                    "region": r.get("region"),
                    "status": r.get("status"),
                    "security_score": r.get(
                        "security_score", 0
                    ),
                    "issue_count": r.get(
                        "issue_count", 0
                    ),
                    "critical_issues": sum(
                        1 for i in r.get(
                            "issues", []
                        )
                        if i["severity"] == "CRITICAL"
                    ),
                    "high_issues": sum(
                        1 for i in r.get(
                            "issues", []
                        )
                        if i["severity"] == "HIGH"
                    ),
                    "guardduty_enabled": r.get(
                        "guardduty_enabled", {}
                    ).get("enabled", False),
                    "vpc_flow_logs": r.get(
                        "vpc_flow_logs", {}
                    ).get("enabled", False),
                    "ecr_scan_on_push": r.get(
                        "ecr_scan_on_push", {}
                    ).get("all_enabled", False),
                    "in_transit_encryption": r.get(
                        "in_transit_encryption", {}
                    ).get("configured", False),
                }

                # Service-specific CSV fields.
                # `data_encryption` means:
                #   ECS -> managed storage KMS encryption
                #   EKS -> secrets envelope encryption
                if ctype == "ecs":
                    row["container_insights"] = (
                        r.get(
                            "container_insights", {}
                        ).get("enabled", False)
                    )
                    row["data_encryption"] = (
                        r.get(
                            "cluster_encryption", {}
                        ).get("kms_enabled", False)
                    )
                    row["privileged_containers"] = (
                        r.get(
                            "privileged_containers",
                            {},
                        ).get(
                            "has_privileged", False
                        )
                    )
                    row["secrets_in_env"] = r.get(
                        "secrets_in_env", {}
                    ).get(
                        "has_plaintext_secrets",
                        False,
                    )
                elif ctype == "eks":
                    row["container_insights"] = ""
                    row["data_encryption"] = (
                        r.get(
                            "secrets_encryption", {}
                        ).get("enabled", False)
                    )
                    row["privileged_containers"] = ""
                    row["secrets_in_env"] = ""

                writer.writerow(row)

        return path

    def _export_html(
        self,
        results: List[Dict],
        summary: Dict,
        timestamp: str,
    ) -> str:
        """Export results as HTML dashboard."""
        path = os.path.join(
            self.output_dir,
            f"container_scan_{self.region}"
            f"_{timestamp}.html",
        )
        self.html_reporter.generate_report(
            results, summary, path
        )
        return path

    def _export_compliance(
        self,
        results: List[Dict],
        timestamp: str,
    ) -> str:
        """Export compliance-focused JSON report."""
        path = os.path.join(
            self.output_dir,
            f"container_compliance_{self.region}"
            f"_{timestamp}.json",
        )

        compliance_data = {
            "scan_time": datetime.now().isoformat(),
            "region": self.region,
            "account_id": self.account_id,
            "total_clusters": len(results),
            "frameworks": {},
        }

        frameworks = [
            "AWS-FSBP",
            "CIS-EKS-v2.0",
            "EKS-Hardening",
            "PCI-DSS-v4.0.1",
            "HIPAA",
            "SOC2",
            "ISO27001",
            "ISO27017",
            "ISO27018",
            "GDPR",
            "NIST-800-53",
        ]

        for fw in frameworks:
            total_pass = 0
            total_fail = 0
            total_controls = 0
            cluster_results = []

            for r in results:
                if r.get("scan_error"):
                    continue
                fw_status = r.get(
                    "compliance_status", {}
                ).get(fw, {})
                if fw_status:
                    total_pass += fw_status.get(
                        "passed_controls", 0
                    )
                    total_fail += fw_status.get(
                        "failed_controls", 0
                    )
                    total_controls = max(
                        total_controls,
                        fw_status.get(
                            "total_controls", 0
                        ),
                    )
                    cluster_results.append({
                        "cluster_name": r.get(
                            "cluster_name"
                        ),
                        "cluster_type": r.get(
                            "cluster_type"
                        ),
                        "compliance_percentage": (
                            fw_status.get(
                                "compliance_"
                                "percentage", 0
                            )
                        ),
                        "is_compliant": (
                            fw_status.get(
                                "is_compliant",
                                False,
                            )
                        ),
                        "failed": fw_status.get(
                            "failed", []
                        ),
                    })

            denom = total_pass + total_fail
            compliance_data["frameworks"][fw] = {
                "total_controls": total_controls,
                "average_pass_rate": (
                    round(
                        total_pass / denom * 100,
                        1,
                    )
                    if denom > 0
                    else 0
                ),
                "cluster_results": cluster_results,
            }

        with open(path, "w") as f:
            json.dump(
                compliance_data,
                f,
                indent=2,
                default=str,
            )
        return path

    # ============================================================
    # Console Summary
    # ============================================================

    def print_summary(
        self, results: List[Dict[str, Any]],
    ) -> None:
        """Print Rich-formatted console summary."""
        summary = self._build_summary(results)
        valid = [
            r for r in results
            if not r.get("scan_error", False)
        ]

        # Overall metrics table
        metrics_table = Table(
            title="Container Security Scan Summary"
        )
        metrics_table.add_column(
            "Metric", style="cyan"
        )
        metrics_table.add_column(
            "Value", justify="right"
        )

        metrics_table.add_row(
            "Region", summary["region"]
        )
        metrics_table.add_row(
            "Account", summary["account_id"]
        )
        metrics_table.add_row(
            "Total Clusters",
            str(summary["total_clusters"]),
        )
        metrics_table.add_row(
            "ECS Clusters",
            str(summary["ecs_clusters"]),
        )
        metrics_table.add_row(
            "EKS Clusters",
            str(summary["eks_clusters"]),
        )
        metrics_table.add_row(
            "Scan Errors",
            str(summary["error_clusters"]),
        )
        metrics_table.add_row(
            "Critical Severity",
            str(
                summary[
                    "critical_severity_clusters"
                ]
            ),
        )
        metrics_table.add_row(
            "High Severity",
            str(
                summary["high_severity_clusters"]
            ),
        )
        metrics_table.add_row(
            "Average Score",
            f"{summary['average_security_score']:.1f}/100",
        )

        self.console.print(metrics_table)

        # ECS Cluster Summary
        ecs_results = [
            r for r in valid
            if r.get("cluster_type") == "ecs"
        ]
        if ecs_results:
            ecs_table = Table(
                title="ECS Cluster Summary"
            )
            ecs_table.add_column(
                "Cluster", style="cyan"
            )
            ecs_table.add_column(
                "Services", justify="right"
            )
            ecs_table.add_column(
                "Score", justify="right"
            )
            ecs_table.add_column(
                "Issues", justify="right"
            )
            ecs_table.add_column("Status")

            for r in ecs_results:
                score = r.get("security_score", 0)
                color = score_to_color(score)
                ecs_table.add_row(
                    r.get("cluster_name", ""),
                    str(r.get("service_count", 0)),
                    f"[{color}]{score}[/{color}]",
                    str(r.get("issue_count", 0)),
                    r.get("status", ""),
                )

            self.console.print(ecs_table)

        # EKS Cluster Summary
        eks_results = [
            r for r in valid
            if r.get("cluster_type") == "eks"
        ]
        if eks_results:
            eks_table = Table(
                title="EKS Cluster Summary"
            )
            eks_table.add_column(
                "Cluster", style="cyan"
            )
            eks_table.add_column(
                "K8s Version", justify="right"
            )
            eks_table.add_column(
                "Node Groups", justify="right"
            )
            eks_table.add_column(
                "Score", justify="right"
            )
            eks_table.add_column(
                "Issues", justify="right"
            )

            for r in eks_results:
                score = r.get("security_score", 0)
                color = score_to_color(score)
                eks_table.add_row(
                    r.get("cluster_name", ""),
                    r.get(
                        "kubernetes_version", ""
                    ),
                    str(
                        r.get("nodegroup_count", 0)
                    ),
                    f"[{color}]{score}[/{color}]",
                    str(r.get("issue_count", 0)),
                )

            self.console.print(eks_table)

        # Lowest scoring clusters
        if valid:
            worst = sorted(
                valid,
                key=lambda r: (
                    r.get("security_score", 0) or 0
                ),
            )[:5]

            score_table = Table(
                title="Lowest Scoring Clusters "
                "(Top 5)"
            )
            score_table.add_column(
                "Cluster", style="cyan"
            )
            score_table.add_column("Type")
            score_table.add_column(
                "Score", justify="right"
            )
            score_table.add_column(
                "Issues", justify="right"
            )
            score_table.add_column("Status")

            for r in worst:
                score = r.get("security_score", 0)
                color = score_to_color(score)
                score_table.add_row(
                    r.get("cluster_name", ""),
                    r.get(
                        "cluster_type", ""
                    ).upper(),
                    f"[{color}]{score}[/{color}]",
                    str(r.get("issue_count", 0)),
                    r.get("status", ""),
                )

            self.console.print(score_table)

        # Compliance summary
        compliance_table = Table(
            title="Compliance Framework Summary"
        )
        compliance_table.add_column(
            "Framework", style="cyan", width=15
        )
        compliance_table.add_column(
            "Compliant",
            justify="center",
            width=10,
        )
        compliance_table.add_column(
            "Total", justify="center", width=10
        )
        compliance_table.add_column(
            "Rate", justify="center", width=10
        )
        compliance_table.add_column(
            "Status", justify="center"
        )

        frameworks = [
            "AWS-FSBP",
            "CIS-EKS-v2.0",
            "EKS-Hardening",
            "PCI-DSS-v4.0.1",
            "HIPAA",
            "SOC2",
            "ISO27001",
            "ISO27017",
            "ISO27018",
            "GDPR",
            "NIST-800-53",
        ]

        for fw in frameworks:
            compliant = 0
            total = 0
            for r in valid:
                fw_status = r.get(
                    "compliance_status", {}
                ).get(fw, {})
                if fw_status:
                    total += 1
                    if fw_status.get(
                        "is_compliant", False
                    ):
                        compliant += 1

            if total == 0:
                continue

            pct = round(
                compliant / total * 100, 1
            )
            if pct >= 90:
                status = (
                    "[green]Excellent[/green]"
                )
            elif pct >= 75:
                status = "[yellow]Good[/yellow]"
            elif pct >= 50:
                status = (
                    "[orange1]Needs Work"
                    "[/orange1]"
                )
            else:
                status = "[red]Poor[/red]"

            compliance_table.add_row(
                fw,
                str(compliant),
                str(total),
                f"{pct}%",
                status,
            )

        self.console.print(compliance_table)
