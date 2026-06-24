"""Tests for Logging & Monitoring Checker (G.3-G.4)."""

import unittest
from unittest.mock import Mock, MagicMock

from ecs_eks_security_scanner.checks.logging_monitoring import (
    LoggingMonitoringChecker,
)


class TestGuardDuty(unittest.TestCase):
    """Test G.3 - GuardDuty check."""

    def setUp(self):
        mock_session = Mock()
        self.mock_client = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = LoggingMonitoringChecker(
            session_factory=lambda: mock_session
        )

    def test_guardduty_enabled(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "DetectorIds": ["abc123"],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        self.mock_client.get_detector.return_value = {
            "Status": "ENABLED",
            "Features": [
                {
                    "Name": "RUNTIME_MONITORING",
                    "Status": "ENABLED",
                    "AdditionalConfiguration": [
                        {
                            "Name": (
                                "ECS_FARGATE_AGENT_MANAGEMENT"
                            ),
                            "Status": "ENABLED",
                        },
                        {
                            "Name": "EKS_ADDON_MANAGEMENT",
                            "Status": "ENABLED",
                        },
                    ],
                },
                {
                    "Name": "EKS_AUDIT_LOGS",
                    "Status": "ENABLED",
                },
            ],
        }
        result = self.checker.check_guardduty(
            "us-east-1"
        )
        self.assertTrue(result["enabled"])
        self.assertTrue(result["ecs_runtime_monitoring"])
        self.assertTrue(result["eks_audit_monitoring"])
        self.assertTrue(result["eks_runtime_monitoring"])

    def test_guardduty_disabled(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "DetectorIds": [],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        result = self.checker.check_guardduty(
            "us-east-1"
        )
        self.assertFalse(result["enabled"])
        self.assertFalse(result["ecs_runtime_monitoring"])
        self.assertFalse(result["eks_audit_monitoring"])
        self.assertFalse(result["eks_runtime_monitoring"])

    def test_guardduty_detector_disabled(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "DetectorIds": ["abc123"],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        self.mock_client.get_detector.return_value = {
            "Status": "DISABLED",
            "Features": [],
        }
        result = self.checker.check_guardduty(
            "us-east-1"
        )
        self.assertFalse(result["enabled"])

    def test_guardduty_partial_features(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "DetectorIds": ["abc123"],
        }]
        self.mock_client.get_paginator.return_value = (
            paginator
        )
        self.mock_client.get_detector.return_value = {
            "Status": "ENABLED",
            "Features": [
                {
                    "Name": "RUNTIME_MONITORING",
                    "Status": "ENABLED",
                    "AdditionalConfiguration": [
                        {
                            "Name": (
                                "ECS_FARGATE_AGENT_MANAGEMENT"
                            ),
                            "Status": "DISABLED",
                        },
                    ],
                },
            ],
        }
        result = self.checker.check_guardduty(
            "us-east-1"
        )
        self.assertTrue(result["enabled"])
        self.assertFalse(result["ecs_runtime_monitoring"])


class TestVpcFlowLogs(unittest.TestCase):
    """Test G.4 - VPC Flow Logs check."""

    def setUp(self):
        mock_session = Mock()
        self.mock_client = Mock()
        mock_session.client.return_value = self.mock_client
        self.checker = LoggingMonitoringChecker(
            session_factory=lambda: mock_session
        )

    def _wire_flow_logs_paginator(self, flow_logs):
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"FlowLogs": flow_logs}
        ]
        self.mock_client.get_paginator.return_value = (
            paginator
        )

    def test_vpc_flow_logs_enabled(self):
        self._wire_flow_logs_paginator([{
            "FlowLogId": "fl-abc123",
            "FlowLogStatus": "ACTIVE",
            "ResourceId": "vpc-abc123",
        }])
        result = self.checker.check_vpc_flow_logs(
            "vpc-abc123", "us-east-1"
        )
        self.assertTrue(result["enabled"])
        self.assertEqual(result["flow_log_count"], 1)

    def test_vpc_flow_logs_disabled(self):
        self._wire_flow_logs_paginator([])
        result = self.checker.check_vpc_flow_logs(
            "vpc-abc123", "us-east-1"
        )
        self.assertFalse(result["enabled"])
        self.assertEqual(result["flow_log_count"], 0)

    def test_vpc_flow_logs_no_vpc_id(self):
        result = self.checker.check_vpc_flow_logs(
            "", "us-east-1"
        )
        self.assertFalse(result["enabled"])

    def test_vpc_flow_logs_inactive(self):
        self._wire_flow_logs_paginator([{
            "FlowLogId": "fl-abc123",
            "FlowLogStatus": "INACTIVE",
        }])
        result = self.checker.check_vpc_flow_logs(
            "vpc-abc123", "us-east-1"
        )
        self.assertFalse(result["enabled"])
        self.assertEqual(result["flow_log_count"], 0)


if __name__ == "__main__":
    unittest.main()
