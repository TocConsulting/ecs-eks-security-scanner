"""Tests for ECS Service Security Checker (C.1-C.5)."""

import unittest

from ecs_eks_security_scanner.checks.ecs_service import (
    ECSServiceChecker,
)


class TestEcsExec(unittest.TestCase):
    """Test C.1 - ECS Exec check."""

    def setUp(self):
        self.checker = ECSServiceChecker()

    def test_ecs_exec_enabled(self):
        service = {
            "serviceName": "web",
            "enableExecuteCommand": True,
        }
        result = self.checker.check_ecs_exec(service)
        self.assertTrue(result["enabled"])
        self.assertEqual(result["service_name"], "web")

    def test_ecs_exec_disabled(self):
        service = {
            "serviceName": "web",
            "enableExecuteCommand": False,
        }
        result = self.checker.check_ecs_exec(service)
        self.assertFalse(result["enabled"])

    def test_ecs_exec_not_set(self):
        service = {"serviceName": "web"}
        result = self.checker.check_ecs_exec(service)
        self.assertFalse(result["enabled"])


class TestPublicIp(unittest.TestCase):
    """Test C.2 - Public IP assignment check."""

    def setUp(self):
        self.checker = ECSServiceChecker()

    def test_public_ip_enabled(self):
        service = {
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "assignPublicIp": "ENABLED",
                    "subnets": ["subnet-abc"],
                }
            }
        }
        result = self.checker.check_public_ip(service)
        self.assertTrue(result["assigns_public_ip"])

    def test_public_ip_disabled(self):
        service = {
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "assignPublicIp": "DISABLED",
                    "subnets": ["subnet-abc"],
                }
            }
        }
        result = self.checker.check_public_ip(service)
        self.assertFalse(result["assigns_public_ip"])

    def test_public_ip_no_config(self):
        service = {}
        result = self.checker.check_public_ip(service)
        self.assertFalse(result["assigns_public_ip"])


class TestCircuitBreaker(unittest.TestCase):
    """Test C.3 - Deployment circuit breaker check."""

    def setUp(self):
        self.checker = ECSServiceChecker()

    def test_circuit_breaker_enabled(self):
        service = {
            "deploymentConfiguration": {
                "deploymentCircuitBreaker": {
                    "enable": True,
                    "rollback": True,
                }
            }
        }
        result = self.checker.check_circuit_breaker(
            service
        )
        self.assertTrue(result["enabled"])
        self.assertTrue(result["rollback_enabled"])

    def test_circuit_breaker_disabled(self):
        service = {
            "deploymentConfiguration": {
                "deploymentCircuitBreaker": {
                    "enable": False,
                    "rollback": False,
                }
            }
        }
        result = self.checker.check_circuit_breaker(
            service
        )
        self.assertFalse(result["enabled"])
        self.assertFalse(result["rollback_enabled"])

    def test_circuit_breaker_not_set(self):
        service = {}
        result = self.checker.check_circuit_breaker(
            service
        )
        self.assertFalse(result["enabled"])


class TestFargatePlatformVersion(unittest.TestCase):
    """Test C.4 - Fargate platform version check."""

    def setUp(self):
        self.checker = ECSServiceChecker()

    def test_fargate_platform_latest(self):
        service = {
            "launchType": "FARGATE",
            "platformVersion": "LATEST",
        }
        result = (
            self.checker.check_fargate_platform_version(
                service
            )
        )
        self.assertTrue(result["is_latest"])
        self.assertEqual(
            result["platform_version"], "LATEST"
        )

    def test_fargate_platform_140(self):
        service = {
            "launchType": "FARGATE",
            "platformVersion": "1.4.0",
        }
        result = (
            self.checker.check_fargate_platform_version(
                service
            )
        )
        self.assertTrue(result["is_latest"])

    def test_fargate_platform_outdated(self):
        service = {
            "launchType": "FARGATE",
            "platformVersion": "1.3.0",
        }
        result = (
            self.checker.check_fargate_platform_version(
                service
            )
        )
        self.assertFalse(result["is_latest"])

    def test_not_fargate(self):
        service = {
            "launchType": "EC2",
            "platformVersion": "",
        }
        result = (
            self.checker.check_fargate_platform_version(
                service
            )
        )
        self.assertTrue(result["is_latest"])
        self.assertEqual(result["launch_type"], "EC2")


class TestSecurityGroups(unittest.TestCase):
    """Test C.5 - Service security groups check."""

    def setUp(self):
        self.checker = ECSServiceChecker()

    def test_security_groups_present(self):
        service = {
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "securityGroups": [
                        "sg-abc123",
                        "sg-def456",
                    ],
                }
            }
        }
        result = self.checker.check_security_groups(
            service
        )
        self.assertTrue(result["has_security_groups"])
        self.assertEqual(
            len(result["security_group_ids"]), 2
        )

    def test_security_groups_missing(self):
        service = {
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "securityGroups": [],
                }
            }
        }
        result = self.checker.check_security_groups(
            service
        )
        self.assertFalse(result["has_security_groups"])

    def test_security_groups_no_config(self):
        service = {}
        result = self.checker.check_security_groups(
            service
        )
        self.assertFalse(result["has_security_groups"])


if __name__ == "__main__":
    unittest.main()
