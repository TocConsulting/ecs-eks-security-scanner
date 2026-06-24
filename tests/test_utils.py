"""Tests for utility functions."""

import os
import tempfile
import unittest

from ecs_eks_security_scanner.utils import (
    get_severity_color,
    score_to_color,
    format_datetime,
    setup_logging,
)


class TestGetSeverityColor(unittest.TestCase):
    """Test severity color mapping."""

    def test_critical_color(self):
        self.assertEqual(
            get_severity_color("CRITICAL"), "bold red"
        )

    def test_high_color(self):
        self.assertEqual(
            get_severity_color("HIGH"), "red"
        )

    def test_medium_color(self):
        self.assertEqual(
            get_severity_color("MEDIUM"), "yellow"
        )

    def test_low_color(self):
        self.assertEqual(
            get_severity_color("LOW"), "blue"
        )

    def test_info_color(self):
        self.assertEqual(
            get_severity_color("INFO"), "cyan"
        )

    def test_error_color(self):
        self.assertEqual(
            get_severity_color("ERROR"), "magenta"
        )

    def test_unknown_color(self):
        self.assertEqual(
            get_severity_color("UNKNOWN"), "white"
        )


class TestScoreToColor(unittest.TestCase):
    """Test score-to-color mapping (matches README
    score interpretation table)."""

    def test_excellent(self):
        self.assertEqual(score_to_color(100), "green")
        self.assertEqual(score_to_color(90), "green")

    def test_good(self):
        self.assertEqual(score_to_color(89), "yellow")
        self.assertEqual(score_to_color(70), "yellow")

    def test_needs_improvement(self):
        self.assertEqual(score_to_color(69), "orange1")
        self.assertEqual(score_to_color(50), "orange1")

    def test_critical(self):
        self.assertEqual(score_to_color(49), "red")
        self.assertEqual(score_to_color(0), "red")

    def test_none_score(self):
        self.assertEqual(score_to_color(None), "white")


class TestFormatDatetime(unittest.TestCase):
    """Test datetime formatting."""

    def test_format_datetime_string(self):
        result = format_datetime(
            "2026-03-11T10:30:00Z"
        )
        self.assertIn("2026-03-11", result)
        self.assertIn("10:30:00", result)
        self.assertIn("UTC", result)

    def test_format_datetime_iso(self):
        result = format_datetime(
            "2026-01-15T08:00:00+00:00"
        )
        self.assertIn("2026-01-15", result)

    def test_format_datetime_plain_string(self):
        result = format_datetime("not-a-date")
        self.assertEqual(result, "not-a-date")

    def test_format_datetime_none(self):
        result = format_datetime(None)
        self.assertEqual(result, "None")

    def test_format_datetime_integer(self):
        result = format_datetime(12345)
        self.assertEqual(result, "12345")


class TestSetupLogging(unittest.TestCase):
    """Test logging setup."""

    def test_setup_logging_creates_logger(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(tmpdir)
            self.assertEqual(
                logger.name,
                "ecs_eks_security_scanner",
            )
            self.assertEqual(len(logger.handlers), 2)

    def test_setup_logging_creates_log_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            setup_logging(tmpdir)
            log_files = [
                f for f in os.listdir(tmpdir)
                if f.endswith(".log")
            ]
            self.assertEqual(len(log_files), 1)
            self.assertTrue(
                log_files[0].startswith("container_scan_")
            )


if __name__ == "__main__":
    unittest.main()
