"""Tests for ECS Task Definition Security Checker (B.1-B.10)."""

import unittest

from ecs_eks_security_scanner.checks.ecs_task import (
    ECSTaskChecker,
)


class TestPrivileged(unittest.TestCase):
    """Test B.1 - Privileged container check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_privileged_true(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "privileged": True},
            ]
        }
        result = self.checker.check_privileged(task_def)
        self.assertTrue(result["has_privileged"])
        self.assertIn("app", result["privileged_containers"])

    def test_privileged_false(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "privileged": False},
            ]
        }
        result = self.checker.check_privileged(task_def)
        self.assertFalse(result["has_privileged"])
        self.assertEqual(result["privileged_containers"], [])

    def test_privileged_not_set(self):
        task_def = {
            "containerDefinitions": [{"name": "app"}]
        }
        result = self.checker.check_privileged(task_def)
        self.assertFalse(result["has_privileged"])

    def test_multiple_containers_one_privileged(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "privileged": False},
                {"name": "sidecar", "privileged": True},
            ]
        }
        result = self.checker.check_privileged(task_def)
        self.assertTrue(result["has_privileged"])
        self.assertIn(
            "sidecar", result["privileged_containers"]
        )
        self.assertNotIn(
            "app", result["privileged_containers"]
        )


class TestRootUser(unittest.TestCase):
    """Test B.2 - Root user check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_root_user_present(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "user": "root"},
            ]
        }
        result = self.checker.check_root_user(task_def)
        self.assertTrue(result["has_root_user"])
        self.assertIn("app", result["root_containers"])

    def test_root_user_not_present(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "user": "1000"},
            ]
        }
        result = self.checker.check_root_user(task_def)
        self.assertFalse(result["has_root_user"])

    def test_root_user_uid_zero(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "user": "0"},
            ]
        }
        result = self.checker.check_root_user(task_def)
        self.assertTrue(result["has_root_user"])

    def test_root_user_not_set(self):
        """No user set defaults to root."""
        task_def = {
            "containerDefinitions": [{"name": "app"}]
        }
        result = self.checker.check_root_user(task_def)
        self.assertTrue(result["has_root_user"])


class TestReadonlyRootFs(unittest.TestCase):
    """Test B.3 - Read-only root filesystem check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_readonly_root_fs_all(self):
        task_def = {
            "containerDefinitions": [
                {
                    "name": "app",
                    "readonlyRootFilesystem": True,
                },
                {
                    "name": "sidecar",
                    "readonlyRootFilesystem": True,
                },
            ]
        }
        result = self.checker.check_readonly_root_fs(
            task_def
        )
        self.assertTrue(result["all_readonly"])
        self.assertEqual(
            result["non_readonly_containers"], []
        )

    def test_readonly_root_fs_not_all(self):
        task_def = {
            "containerDefinitions": [
                {
                    "name": "app",
                    "readonlyRootFilesystem": True,
                },
                {
                    "name": "sidecar",
                    "readonlyRootFilesystem": False,
                },
            ]
        }
        result = self.checker.check_readonly_root_fs(
            task_def
        )
        self.assertFalse(result["all_readonly"])
        self.assertIn(
            "sidecar", result["non_readonly_containers"]
        )

    def test_readonly_root_fs_not_set(self):
        task_def = {
            "containerDefinitions": [{"name": "app"}]
        }
        result = self.checker.check_readonly_root_fs(
            task_def
        )
        self.assertFalse(result["all_readonly"])


class TestLinuxCapabilities(unittest.TestCase):
    """Test B.4 - Linux capabilities check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_linux_capabilities_dangerous(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "linuxParameters": {
                    "capabilities": {
                        "add": ["SYS_ADMIN", "NET_RAW"],
                    }
                },
            }]
        }
        result = self.checker.check_linux_capabilities(
            task_def
        )
        self.assertTrue(result["has_dangerous_caps"])
        self.assertIn(
            "SYS_ADMIN", result["dangerous_caps_found"]
        )
        self.assertIn(
            "app", result["violating_containers"]
        )

    def test_linux_capabilities_clean(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "linuxParameters": {
                    "capabilities": {
                        "add": ["CHOWN"],
                        "drop": ["ALL"],
                    }
                },
            }]
        }
        result = self.checker.check_linux_capabilities(
            task_def
        )
        self.assertFalse(result["has_dangerous_caps"])
        self.assertEqual(
            result["dangerous_caps_found"], []
        )

    def test_linux_capabilities_no_params(self):
        task_def = {
            "containerDefinitions": [{"name": "app"}]
        }
        result = self.checker.check_linux_capabilities(
            task_def
        )
        self.assertFalse(result["has_dangerous_caps"])


class TestNetworkMode(unittest.TestCase):
    """Test B.5 - Network mode check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_network_mode_awsvpc(self):
        task_def = {"networkMode": "awsvpc"}
        result = self.checker.check_network_mode(task_def)
        self.assertTrue(result["is_awsvpc"])
        self.assertEqual(result["network_mode"], "awsvpc")

    def test_network_mode_bridge(self):
        task_def = {"networkMode": "bridge"}
        result = self.checker.check_network_mode(task_def)
        self.assertFalse(result["is_awsvpc"])
        self.assertEqual(result["network_mode"], "bridge")

    def test_network_mode_default(self):
        task_def = {}
        result = self.checker.check_network_mode(task_def)
        self.assertFalse(result["is_awsvpc"])
        self.assertEqual(result["network_mode"], "bridge")


class TestLogging(unittest.TestCase):
    """Test B.6 - Container logging check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_logging_configured(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": "/ecs/app",
                    },
                },
            }]
        }
        result = self.checker.check_logging(task_def)
        self.assertTrue(result["all_configured"])
        self.assertEqual(
            result["unlogged_containers"], []
        )

    def test_logging_missing(self):
        task_def = {
            "containerDefinitions": [{"name": "app"}]
        }
        result = self.checker.check_logging(task_def)
        self.assertFalse(result["all_configured"])
        self.assertIn("app", result["unlogged_containers"])

    def test_logging_no_driver(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "logConfiguration": {},
            }]
        }
        result = self.checker.check_logging(task_def)
        self.assertFalse(result["all_configured"])


class TestSecretsInEnv(unittest.TestCase):
    """Test B.7 - Secrets in environment variables check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_secrets_found(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "environment": [
                    {
                        "name": "AWS_SECRET_ACCESS_KEY",
                        "value": "wJalrXUtnFEMI/K7MDENG",
                    },
                ],
            }]
        }
        result = self.checker.check_secrets_in_env(
            task_def
        )
        self.assertTrue(result["has_plaintext_secrets"])
        self.assertGreater(result["finding_count"], 0)

    def test_secrets_clean(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "environment": [
                    {"name": "APP_PORT", "value": "8080"},
                    {"name": "LOG_LEVEL", "value": "info"},
                ],
            }]
        }
        result = self.checker.check_secrets_in_env(
            task_def
        )
        self.assertFalse(result["has_plaintext_secrets"])
        self.assertEqual(result["finding_count"], 0)

    def test_secrets_password_pattern(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "environment": [
                    {
                        "name": "DB_PASSWORD",
                        "value": "s3cret",
                    },
                ],
            }]
        }
        result = self.checker.check_secrets_in_env(
            task_def
        )
        self.assertTrue(result["has_plaintext_secrets"])

    def test_secrets_no_env(self):
        task_def = {
            "containerDefinitions": [{"name": "app"}]
        }
        result = self.checker.check_secrets_in_env(
            task_def
        )
        self.assertFalse(result["has_plaintext_secrets"])


class TestResourceLimits(unittest.TestCase):
    """Test B.8 - Resource limits check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_resource_limits_defined(self):
        task_def = {
            "cpu": "256",
            "memory": "512",
            "containerDefinitions": [{"name": "app"}],
        }
        result = self.checker.check_resource_limits(
            task_def
        )
        self.assertTrue(result["all_defined"])
        self.assertTrue(result["has_task_level_limits"])

    def test_resource_limits_missing(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "cpu": 0},
            ]
        }
        result = self.checker.check_resource_limits(
            task_def
        )
        self.assertFalse(result["all_defined"])
        self.assertFalse(result["has_task_level_limits"])
        self.assertIn(
            "app", result["missing_limits_containers"]
        )

    def test_resource_limits_container_level(self):
        task_def = {
            "containerDefinitions": [{
                "name": "app",
                "cpu": 256,
                "memory": 512,
            }]
        }
        result = self.checker.check_resource_limits(
            task_def
        )
        self.assertTrue(result["all_defined"])


class TestPidMode(unittest.TestCase):
    """Test B.9 - PID mode check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_pid_mode_host(self):
        task_def = {"pidMode": "host"}
        result = self.checker.check_pid_mode(task_def)
        self.assertTrue(result["has_host_pid"])
        self.assertEqual(result["pid_mode"], "host")

    def test_pid_mode_task(self):
        task_def = {"pidMode": "task"}
        result = self.checker.check_pid_mode(task_def)
        self.assertFalse(result["has_host_pid"])
        self.assertEqual(result["pid_mode"], "task")

    def test_pid_mode_not_set(self):
        task_def = {}
        result = self.checker.check_pid_mode(task_def)
        self.assertFalse(result["has_host_pid"])


class TestExecutionRole(unittest.TestCase):
    """Test B.10 - Execution role check."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_execution_role_present(self):
        task_def = {
            "executionRoleArn": (
                "arn:aws:iam::123456789012:"
                "role/ecsTaskExecutionRole"
            ),
        }
        result = self.checker.check_execution_role(
            task_def
        )
        self.assertTrue(result["has_execution_role"])
        self.assertIsNotNone(result["execution_role_arn"])

    def test_execution_role_missing(self):
        task_def = {}
        result = self.checker.check_execution_role(
            task_def
        )
        self.assertFalse(result["has_execution_role"])
        self.assertIsNone(result["execution_role_arn"])


class TestCheckAll(unittest.TestCase):
    """Test check_all returns all sub-check keys."""

    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_check_all_keys(self):
        task_def = {
            "containerDefinitions": [{"name": "app"}],
        }
        result = self.checker.check_all(task_def)
        expected_keys = [
            "privileged", "root_user", "readonly_root_fs",
            "linux_capabilities", "network_mode", "logging",
            "secrets_in_env", "resource_limits", "pid_mode",
            "execution_role",
        ]
        for key in expected_keys:
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
