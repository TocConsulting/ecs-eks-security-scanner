"""ECS Service Security Checker - C.1-C.5."""

from typing import Dict, Any

from .base import BaseChecker


class ECSServiceChecker(BaseChecker):
    """Check ECS service-level security configuration."""

    def check_ecs_exec(
        self, service: Dict[str, Any]
    ) -> Dict[str, Any]:
        """C.1 - Check enableExecuteCommand."""
        try:
            enabled = service.get(
                "enableExecuteCommand", False
            )
            return {
                "enabled": enabled,
                "service_name": service.get("serviceName", ""),
            }
        except Exception as e:
            self.logger.warning(
                f"ECS Exec check failed: {e}"
            )
            return {
                "enabled": True,
                "service_name": "",
                "error": str(e),
            }

    def check_public_ip(
        self, service: Dict[str, Any]
    ) -> Dict[str, Any]:
        """C.2 - Check assignPublicIp in networkConfiguration."""
        try:
            net_config = service.get(
                "networkConfiguration", {}
            )
            awsvpc_config = net_config.get(
                "awsvpcConfiguration", {}
            )
            assign_public = awsvpc_config.get(
                "assignPublicIp", "DISABLED"
            )
            return {
                "assigns_public_ip": assign_public == "ENABLED",
                "assign_public_ip_value": assign_public,
            }
        except Exception as e:
            self.logger.warning(
                f"Public IP check failed: {e}"
            )
            return {
                "assigns_public_ip": True,
                "assign_public_ip_value": "UNKNOWN",
                "error": str(e),
            }

    def check_circuit_breaker(
        self, service: Dict[str, Any]
    ) -> Dict[str, Any]:
        """C.3 - Check deploymentCircuitBreaker."""
        try:
            deploy_config = service.get(
                "deploymentConfiguration", {}
            )
            circuit_breaker = deploy_config.get(
                "deploymentCircuitBreaker", {}
            )
            enabled = circuit_breaker.get("enable", False)
            rollback = circuit_breaker.get("rollback", False)
            return {
                "enabled": enabled,
                "rollback_enabled": rollback,
            }
        except Exception as e:
            self.logger.warning(
                f"Circuit breaker check failed: {e}"
            )
            return {
                "enabled": False,
                "rollback_enabled": False,
                "error": str(e),
            }

    def check_fargate_platform_version(
        self, service: Dict[str, Any]
    ) -> Dict[str, Any]:
        """C.4 - Check platformVersion is LATEST.

        Linux Fargate LATEST = 1.4.0.
        Windows Fargate LATEST = 1.0.0.
        Sources:
         - https://docs.aws.amazon.com/AmazonECS/latest/
           developerguide/platform_versions.html
         - https://docs.aws.amazon.com/AmazonECS/latest/
           developerguide/platform_versions_windows.html
        """
        try:
            launch_type = service.get("launchType", "")
            platform_version = service.get(
                "platformVersion", ""
            )
            platform_family = (
                service.get("platformFamily", "")
                or ""
            ).upper()
            # Only applicable to Fargate services
            if launch_type != "FARGATE":
                return {
                    "is_latest": True,
                    "platform_version": "N/A (not Fargate)",
                    "launch_type": launch_type,
                }
            if "WINDOWS" in platform_family:
                latest_versions = ("LATEST", "1.0.0")
            else:
                latest_versions = ("LATEST", "1.4.0")
            is_latest = platform_version in latest_versions
            return {
                "is_latest": is_latest,
                "platform_version": platform_version,
                "launch_type": launch_type,
                "platform_family": platform_family,
            }
        except Exception as e:
            self.logger.warning(
                f"Platform version check failed: {e}"
            )
            return {
                "is_latest": False,
                "platform_version": "unknown",
                "launch_type": "unknown",
                "error": str(e),
            }

    def check_security_groups(
        self, service: Dict[str, Any]
    ) -> Dict[str, Any]:
        """C.5 - Check securityGroups in networkConfiguration."""
        try:
            net_config = service.get(
                "networkConfiguration", {}
            )
            awsvpc_config = net_config.get(
                "awsvpcConfiguration", {}
            )
            security_groups = awsvpc_config.get(
                "securityGroups", []
            )
            return {
                "has_security_groups": len(security_groups) > 0,
                "security_group_ids": security_groups,
            }
        except Exception as e:
            self.logger.warning(
                f"Security groups check failed: {e}"
            )
            return {
                "has_security_groups": False,
                "security_group_ids": [],
                "error": str(e),
            }

    def check_all(
        self, service: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run all C.1-C.5 checks on a single ECS service."""
        return {
            "ecs_exec": self.check_ecs_exec(service),
            "public_ip": self.check_public_ip(service),
            "circuit_breaker": self.check_circuit_breaker(service),
            "fargate_platform_version": self.check_fargate_platform_version(service),
            "security_groups": self.check_security_groups(service),
        }
