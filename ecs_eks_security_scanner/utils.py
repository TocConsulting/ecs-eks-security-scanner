"""Utility functions for ECS/EKS Security Scanner."""

import logging
import os
from datetime import datetime
from typing import Dict, Any


def setup_logging(output_dir: str) -> logging.Logger:
    """Setup logging configuration with console and file handlers."""
    logger = logging.getLogger("ecs_eks_security_scanner")
    logger.setLevel(logging.INFO)

    # Prevent propagation to root logger to avoid duplicates
    logger.propagate = False

    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    log_file = os.path.join(
        output_dir,
        f'container_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


def calculate_ecs_security_score(
    checks: Dict[str, Any],
) -> int:
    """Calculate a security score for an ECS cluster (0-100).

    Score starts at 100 and deducts based on findings.
    Score is clamped to minimum 0 (never negative).
    """
    score = 100

    def get(check_name: str, key: str, default=False):
        check = checks.get(check_name, {})
        if isinstance(check, dict) and "error" not in check:
            return check.get(key, default)
        return default

    # A. Cluster Configuration
    if not get("container_insights", "enabled"):
        score -= 5      # A.1 MEDIUM
    if not get("execute_command_logging", "configured"):
        score -= 10     # A.2 HIGH
    if not get("cluster_encryption", "kms_enabled"):
        score -= 5      # A.3 MEDIUM
    if not get("capacity_provider_strategy", "has_strategy"):
        score -= 2      # A.4 LOW
    if not get("service_connect_namespace", "configured"):
        score -= 2      # A.5 LOW

    # B. Task Definition Security
    if get("privileged_containers", "has_privileged"):
        score -= 20     # B.1 CRITICAL
    if get("root_user_containers", "has_root_user"):
        score -= 15     # B.2 HIGH
    if not get("readonly_root_fs", "all_readonly"):
        score -= 10     # B.3 HIGH
    if get("linux_capabilities", "has_dangerous_caps"):
        score -= 10     # B.4 HIGH
    if not get("network_mode", "all_awsvpc"):
        score -= 15     # B.5 HIGH
    if not get("container_logging", "all_configured"):
        score -= 10     # B.6 HIGH
    if get("secrets_in_env", "has_plaintext_secrets"):
        score -= 20     # B.7 CRITICAL
    if not get("resource_limits", "all_defined"):
        score -= 5      # B.8 MEDIUM
    if get("pid_mode", "has_host_pid"):
        score -= 10     # B.9 HIGH
    if not get("execution_role", "all_configured"):
        score -= 10     # B.10 HIGH

    # C. Service Security
    # C.1: Only penalize if exec is enabled AND logging
    # is NOT configured (cross-reference A.2)
    if (
        get("ecs_exec_enabled", "any_enabled")
        and not get(
            "execute_command_logging", "configured"
        )
    ):
        score -= 5      # C.1 MEDIUM
    if get("public_ip_assignment", "any_public"):
        score -= 15     # C.2 HIGH
    if not get("circuit_breaker", "all_enabled"):
        score -= 5      # C.3 MEDIUM
    if not get("fargate_platform_version", "all_latest"):
        score -= 5      # C.4 MEDIUM
    if not get("service_security_groups", "all_configured"):
        score -= 10     # C.5 HIGH

    # F. IAM
    if not get("role_separation", "separated"):
        score -= 10     # F.1 HIGH
    if get("overly_permissive_roles", "has_admin_roles"):
        score -= 20     # F.2 CRITICAL
    if get("execution_policy_on_task", "has_violation"):
        score -= 5      # F.4 MEDIUM

    # G. Logging
    if not get("guardduty_enabled", "enabled"):
        score -= 10     # G.3 HIGH
    if not get("vpc_flow_logs", "enabled"):
        score -= 5      # G.4 MEDIUM

    # H. Data Protection
    if not get("ecr_scan_on_push", "all_enabled"):
        score -= 10     # H.2 HIGH
    if not get(
        "ecr_enhanced_scanning", "enhanced_enabled"
    ):
        score -= 5      # H.2b MEDIUM
    if not get("ecr_tag_immutability", "all_immutable"):
        score -= 5      # H.3 MEDIUM
    if not get("in_transit_encryption", "configured"):
        score -= 5      # H.4 MEDIUM

    return max(0, score)


def calculate_eks_security_score(
    checks: Dict[str, Any],
) -> int:
    """Calculate a security score for an EKS cluster (0-100).

    Score starts at 100 and deducts based on findings.
    Score is clamped to minimum 0 (never negative).
    """
    score = 100

    def get(check_name: str, key: str, default=False):
        check = checks.get(check_name, {})
        if isinstance(check, dict) and "error" not in check:
            return check.get(key, default)
        return default

    # D. EKS Cluster Configuration
    if get("endpoint_public_access", "unrestricted"):
        score -= 20     # D.1 CRITICAL
    if not get("endpoint_private_access", "enabled"):
        score -= 10     # D.2 HIGH
    if not get("secrets_encryption", "enabled"):
        score -= 15     # D.3 HIGH
    if not get("control_plane_logging", "all_enabled"):
        score -= 10     # D.4 HIGH
    if get("kubernetes_version_check", "is_eol"):
        score -= 20     # D.5 CRITICAL (truly EOL)
    elif get(
        "kubernetes_version_check", "extended_support"
    ):
        score -= 10     # D.5 HIGH (extended support, paid)
    if not get("cluster_security_group", "configured"):
        score -= 5      # D.6 MEDIUM
    if not get("managed_addons", "all_present"):
        score -= 2      # D.7 LOW
    # D.8: Only check if Fargate profiles exist
    if (
        get("fargate_profiles", "has_profiles")
        and not get(
            "fargate_profiles", "private_subnets_only"
        )
    ):
        score -= 5      # D.8 MEDIUM

    # E. Node Group Security
    if get("nodegroup_remote_access", "any_unrestricted"):
        score -= 15     # E.1 HIGH
    if not get(
        "nodegroup_disk_encryption", "all_encrypted"
    ):
        score -= 10     # E.2 HIGH
    if not get("nodegroup_ami_type", "all_secure"):
        score -= 5      # E.3 MEDIUM
    if not get(
        "nodegroup_launch_template", "all_use_template"
    ):
        score -= 2      # E.4 LOW

    # F. IAM
    if not get("oidc_provider", "configured"):
        score -= 15     # F.3 HIGH
    if get("overly_permissive_roles", "has_admin_roles"):
        score -= 20     # F.2 CRITICAL
    if get(
        "cluster_role_permissions", "overly_permissive"
    ):
        score -= 5      # F.5 MEDIUM

    # G. Logging
    if not get("guardduty_enabled", "enabled"):
        score -= 10     # G.3 HIGH
    if not get("vpc_flow_logs", "enabled"):
        score -= 5      # G.4 MEDIUM

    # H. Data Protection
    if not get("ecr_scan_on_push", "all_enabled"):
        score -= 10     # H.2 HIGH
    if not get(
        "ecr_enhanced_scanning", "enhanced_enabled"
    ):
        score -= 5      # H.2b MEDIUM
    if not get("ecr_tag_immutability", "all_immutable"):
        score -= 5      # H.3 MEDIUM
    if not get("in_transit_encryption", "configured"):
        score -= 5      # H.4 MEDIUM

    return max(0, score)


def get_severity_color(severity: str) -> str:
    """Map severity level to Rich color string."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
        "ERROR": "magenta",
    }
    return colors.get(severity, "white")


def score_to_color(score: int) -> str:
    """Map a 0-100 security score to a Rich color.

    Matches the README's score interpretation table:
      90-100 Excellent (green), 70-89 Good (yellow),
      50-69 Needs Improvement (orange1), 0-49 Critical (red).
    """
    if score is None:
        return "white"
    if score >= 90:
        return "green"
    if score >= 70:
        return "yellow"
    if score >= 50:
        return "orange1"
    return "red"


def format_datetime(dt) -> str:
    """Format datetime for display."""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(
                dt.replace("Z", "+00:00")
            )
        except ValueError:
            return dt

    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    return str(dt)
