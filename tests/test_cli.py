"""Tests for CLI interface."""

import unittest
from unittest.mock import patch, Mock
from click.testing import CliRunner

from ecs_eks_security_scanner.cli import cli


class TestCLI(unittest.TestCase):
    """Test CLI commands and options."""

    def setUp(self):
        self.runner = CliRunner()

    def test_help_output(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "ECS/EKS Security Scanner", result.output
        )
        self.assertIn("security", result.output)

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("1.0.0", result.output)

    def test_security_help(self):
        result = self.runner.invoke(
            cli, ["security", "--help"]
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("cluster", result.output)
        self.assertIn("exclude-cluster", result.output)
        self.assertIn("compliance-only", result.output)
        self.assertIn("region", result.output)
        self.assertIn("profile", result.output)
        self.assertIn("output-format", result.output)
        self.assertIn("service", result.output)

    def test_security_invalid_format(self):
        result = self.runner.invoke(
            cli, ["security", "-f", "xml"]
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_security_invalid_service(self):
        result = self.runner.invoke(
            cli, ["security", "-s", "lambda"]
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_help_short_flag(self):
        result = self.runner.invoke(cli, ["-h"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "ECS/EKS Security Scanner", result.output
        )


if __name__ == "__main__":
    unittest.main()
