"""Tool adapters: one per external tool (FR4, FR6, FR7, FR17).

Agents reach Docker, pytest, Bandit, pip-audit and the sandbox only through this package,
so every adapter can be replaced with a fake in tests.
"""

from devsecops.tools.bandit_scanner import BanditScanner
from devsecops.tools.base import CommandResult, ScanOutput, ToolError, run_command
from devsecops.tools.docker_client import DockerClient, DockerError
from devsecops.tools.health_checker import HealthChecker
from devsecops.tools.injection_detector import InjectionDetector
from devsecops.tools.pip_audit_scanner import PipAuditScanner
from devsecops.tools.pytest_runner import PytestRunner
from devsecops.tools.sandbox import MonitorResult, Sandbox, watch_health

__all__ = [
    "BanditScanner",
    "CommandResult",
    "DockerClient",
    "DockerError",
    "HealthChecker",
    "InjectionDetector",
    "MonitorResult",
    "PipAuditScanner",
    "PytestRunner",
    "Sandbox",
    "ScanOutput",
    "ToolError",
    "run_command",
    "watch_health",
]
