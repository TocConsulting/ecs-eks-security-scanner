"""ECS Cluster Security Checker - A.1-A.5."""

from typing import Dict, Any

from .base import BaseChecker


class ECSClusterChecker(BaseChecker):
    """Check ECS cluster-level security configuration."""

    def check_container_insights(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """A.1 - Check if Container Insights is enabled.

        Accepts both classic 'enabled' and the upgraded
        'enhanced' tier (Container Insights v2).
        """
        try:
            settings = cluster.get("settings", [])
            enabled = any(
                s.get("name") == "containerInsights"
                and s.get("value") in ("enabled", "enhanced")
                for s in settings
            )
            return {"enabled": enabled}
        except Exception as e:
            self.logger.warning(
                f"Container Insights check failed: {e}"
            )
            return {"enabled": False, "error": str(e)}

    def check_execute_command_logging(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """A.2 - Check executeCommandConfiguration logging."""
        try:
            config = cluster.get("configuration", {})
            exec_config = config.get(
                "executeCommandConfiguration", {}
            )
            logging_type = exec_config.get("logging", "NONE")
            log_config = exec_config.get("logConfiguration", {})
            has_log_config = bool(
                log_config.get("cloudWatchLogGroupName")
                or log_config.get("s3BucketName")
            )
            configured = logging_type != "NONE" or has_log_config
            return {
                "configured": configured,
                "logging_type": logging_type,
                "has_log_config": has_log_config,
            }
        except Exception as e:
            self.logger.warning(
                f"Execute command logging check failed: {e}"
            )
            return {
                "configured": False,
                "logging_type": "NONE",
                "has_log_config": False,
                "error": str(e),
            }

    def check_cluster_encryption(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """A.3 - Check managedStorageConfiguration KMS."""
        try:
            config = cluster.get("configuration", {})
            storage_config = config.get(
                "managedStorageConfiguration", {}
            )
            kms_key_id = storage_config.get("kmsKeyId")
            fargate_ephemeral = storage_config.get(
                "fargateEphemeralStorageKmsKeyId"
            )
            kms_enabled = bool(kms_key_id or fargate_ephemeral)
            return {
                "kms_enabled": kms_enabled,
                "kms_key_id": kms_key_id,
            }
        except Exception as e:
            self.logger.warning(
                f"Cluster encryption check failed: {e}"
            )
            return {
                "kms_enabled": False,
                "kms_key_id": None,
                "error": str(e),
            }

    def check_capacity_provider_strategy(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """A.4 - Check defaultCapacityProviderStrategy."""
        try:
            strategy = cluster.get(
                "defaultCapacityProviderStrategy", []
            )
            providers = [
                s.get("capacityProvider", "")
                for s in strategy
            ]
            return {
                "has_strategy": len(strategy) > 0,
                "providers": providers,
            }
        except Exception as e:
            self.logger.warning(
                f"Capacity provider check failed: {e}"
            )
            return {
                "has_strategy": False,
                "providers": [],
                "error": str(e),
            }

    def check_service_connect_namespace(
        self, cluster: Dict[str, Any]
    ) -> Dict[str, Any]:
        """A.5 - Check serviceConnectDefaults."""
        try:
            sc_defaults = cluster.get(
                "serviceConnectDefaults", {}
            )
            namespace = sc_defaults.get("namespace")
            return {
                "configured": bool(namespace),
                "namespace": namespace,
            }
        except Exception as e:
            self.logger.warning(
                f"Service Connect check failed: {e}"
            )
            return {
                "configured": False,
                "namespace": None,
                "error": str(e),
            }
