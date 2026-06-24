"""Tests for ECS Cluster Security Checker (A.1-A.5)."""

import unittest

from ecs_eks_security_scanner.checks.ecs_cluster import (
    ECSClusterChecker,
)


class TestContainerInsights(unittest.TestCase):
    """Test A.1 - Container Insights check."""

    def setUp(self):
        self.checker = ECSClusterChecker()

    def test_container_insights_enabled(self):
        cluster = {
            "settings": [
                {
                    "name": "containerInsights",
                    "value": "enabled",
                }
            ]
        }
        result = self.checker.check_container_insights(cluster)
        self.assertTrue(result["enabled"])

    def test_container_insights_disabled(self):
        cluster = {
            "settings": [
                {
                    "name": "containerInsights",
                    "value": "disabled",
                }
            ]
        }
        result = self.checker.check_container_insights(cluster)
        self.assertFalse(result["enabled"])

    def test_container_insights_missing_settings(self):
        cluster = {}
        result = self.checker.check_container_insights(cluster)
        self.assertFalse(result["enabled"])

    def test_container_insights_empty_settings(self):
        cluster = {"settings": []}
        result = self.checker.check_container_insights(cluster)
        self.assertFalse(result["enabled"])


class TestExecuteCommandLogging(unittest.TestCase):
    """Test A.2 - Execute command logging check."""

    def setUp(self):
        self.checker = ECSClusterChecker()

    def test_execute_command_logging_configured(self):
        cluster = {
            "configuration": {
                "executeCommandConfiguration": {
                    "logging": "OVERRIDE",
                    "logConfiguration": {
                        "cloudWatchLogGroupName": "/ecs/exec",
                    },
                }
            }
        }
        result = self.checker.check_execute_command_logging(
            cluster
        )
        self.assertTrue(result["configured"])
        self.assertEqual(result["logging_type"], "OVERRIDE")
        self.assertTrue(result["has_log_config"])

    def test_execute_command_logging_not_configured(self):
        cluster = {}
        result = self.checker.check_execute_command_logging(
            cluster
        )
        self.assertFalse(result["configured"])
        self.assertEqual(result["logging_type"], "NONE")
        self.assertFalse(result["has_log_config"])

    def test_execute_command_logging_s3(self):
        cluster = {
            "configuration": {
                "executeCommandConfiguration": {
                    "logging": "NONE",
                    "logConfiguration": {
                        "s3BucketName": "my-exec-logs",
                    },
                }
            }
        }
        result = self.checker.check_execute_command_logging(
            cluster
        )
        self.assertTrue(result["configured"])
        self.assertTrue(result["has_log_config"])

    def test_execute_command_logging_type_only(self):
        cluster = {
            "configuration": {
                "executeCommandConfiguration": {
                    "logging": "DEFAULT",
                }
            }
        }
        result = self.checker.check_execute_command_logging(
            cluster
        )
        self.assertTrue(result["configured"])
        self.assertFalse(result["has_log_config"])


class TestClusterEncryption(unittest.TestCase):
    """Test A.3 - Cluster encryption check."""

    def setUp(self):
        self.checker = ECSClusterChecker()

    def test_cluster_encryption_enabled(self):
        cluster = {
            "configuration": {
                "managedStorageConfiguration": {
                    "kmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                }
            }
        }
        result = self.checker.check_cluster_encryption(cluster)
        self.assertTrue(result["kms_enabled"])
        self.assertIsNotNone(result["kms_key_id"])

    def test_cluster_encryption_disabled(self):
        cluster = {}
        result = self.checker.check_cluster_encryption(cluster)
        self.assertFalse(result["kms_enabled"])
        self.assertIsNone(result["kms_key_id"])

    def test_cluster_encryption_fargate_ephemeral(self):
        cluster = {
            "configuration": {
                "managedStorageConfiguration": {
                    "fargateEphemeralStorageKmsKeyId": (
                        "arn:aws:kms:us-east-1:123:key/def"
                    ),
                }
            }
        }
        result = self.checker.check_cluster_encryption(cluster)
        self.assertTrue(result["kms_enabled"])


class TestCapacityProviderStrategy(unittest.TestCase):
    """Test A.4 - Capacity provider strategy check."""

    def setUp(self):
        self.checker = ECSClusterChecker()

    def test_capacity_provider_strategy_present(self):
        cluster = {
            "defaultCapacityProviderStrategy": [
                {"capacityProvider": "FARGATE", "weight": 1},
            ]
        }
        result = (
            self.checker.check_capacity_provider_strategy(
                cluster
            )
        )
        self.assertTrue(result["has_strategy"])
        self.assertIn("FARGATE", result["providers"])

    def test_capacity_provider_strategy_missing(self):
        cluster = {}
        result = (
            self.checker.check_capacity_provider_strategy(
                cluster
            )
        )
        self.assertFalse(result["has_strategy"])
        self.assertEqual(result["providers"], [])

    def test_capacity_provider_strategy_empty(self):
        cluster = {"defaultCapacityProviderStrategy": []}
        result = (
            self.checker.check_capacity_provider_strategy(
                cluster
            )
        )
        self.assertFalse(result["has_strategy"])


class TestServiceConnectNamespace(unittest.TestCase):
    """Test A.5 - Service Connect namespace check."""

    def setUp(self):
        self.checker = ECSClusterChecker()

    def test_service_connect_configured(self):
        cluster = {
            "serviceConnectDefaults": {
                "namespace": (
                    "arn:aws:servicediscovery:us-east-1:"
                    "123:namespace/ns-abc"
                ),
            }
        }
        result = (
            self.checker.check_service_connect_namespace(
                cluster
            )
        )
        self.assertTrue(result["configured"])
        self.assertIsNotNone(result["namespace"])

    def test_service_connect_not_configured(self):
        cluster = {}
        result = (
            self.checker.check_service_connect_namespace(
                cluster
            )
        )
        self.assertFalse(result["configured"])
        self.assertIsNone(result["namespace"])

    def test_service_connect_empty_namespace(self):
        cluster = {"serviceConnectDefaults": {}}
        result = (
            self.checker.check_service_connect_namespace(
                cluster
            )
        )
        self.assertFalse(result["configured"])


if __name__ == "__main__":
    unittest.main()
