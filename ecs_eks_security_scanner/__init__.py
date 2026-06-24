"""ECS/EKS Security Scanner - Comprehensive AWS container security
auditing tool with multi-framework compliance mapping."""

__version__ = "1.0.0"
__author__ = "Toc Consulting"
__email__ = "tarek@tocconsulting.fr"

from .scanner import ContainerSecurityScanner
from .compliance import ComplianceChecker

__all__ = ["ContainerSecurityScanner", "ComplianceChecker"]
