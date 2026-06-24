"""ECS Task Definition Security Checker - B.1-B.10."""

import re
from typing import Dict, Any

from .base import BaseChecker


class ECSTaskChecker(BaseChecker):
    """Check ECS task definition security configuration."""

    SECRET_NAME_PATTERNS = [
        r"AWS_ACCESS_KEY_ID",
        r"AWS_SECRET_ACCESS_KEY",
        r"ECS_ENGINE_AUTH_DATA",
        r".*PASSWORD.*",
        r".*SECRET.*",
        r".*TOKEN.*",
        r".*API_KEY.*",
        r".*PRIVATE_KEY.*",
        r".*DATABASE_URL.*",
        r".*CONNECTION_STRING.*",
        r".*CREDENTIALS.*",
    ]

    # Patterns matched against env-var VALUES. The 4-char
    # prefixes are AWS-issued IAM/STS credential identifiers
    # per https://docs.aws.amazon.com/IAM/latest/UserGuide/
    # reference_identifiers.html.
    SECRET_VALUE_PATTERNS = [
        (
            r"^(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)"
            r"[A-Z0-9]{16}$",
            "AWS access key",
        ),
        (
            r"-----BEGIN (RSA |DSA |EC |OPENSSH |"
            r"PGP |ENCRYPTED )?PRIVATE KEY-----",
            "private key block",
        ),
        (
            r"^gh[pousr]_[A-Za-z0-9]{36,}$",
            "GitHub token",
        ),
        (
            r"^xox[abprs]-[A-Za-z0-9-]{10,}$",
            "Slack token",
        ),
    ]

    # Backwards-compat alias retained for any external code
    # referencing the older name.
    SECRET_PATTERNS = SECRET_NAME_PATTERNS

    # Aligned with CIS Docker Benchmark 5.3, kube-bench and
    # Falco default ruleset. DAC_OVERRIDE, SETUID/SETGID,
    # BPF, PERFMON are top-risk capabilities flagged by all
    # three sources.
    # Sources:
    #  - https://man7.org/linux/man-pages/man7/capabilities.7.html
    #  - CIS Docker Benchmark section 5.3
    DANGEROUS_CAPABILITIES = [
        "ALL",
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "SYS_TIME",
        "SYS_CHROOT",
        "NET_ADMIN",
        "NET_RAW",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "SETUID",
        "SETGID",
        "SETFCAP",
        "MKNOD",
        "AUDIT_WRITE",
        "BPF",
        "PERFMON",
        "IPC_LOCK",
        "IPC_OWNER",
        "LINUX_IMMUTABLE",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "BLOCK_SUSPEND",
        "WAKE_ALARM",
    ]

    def check_privileged(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.1 - Check privileged flag on all containers."""
        try:
            containers = task_def.get(
                "containerDefinitions", []
            )
            privileged_containers = []
            for c in containers:
                if c.get("privileged", False):
                    privileged_containers.append(c.get("name", ""))
            return {
                "has_privileged": len(privileged_containers) > 0,
                "privileged_containers": privileged_containers,
            }
        except Exception as e:
            self.logger.warning(
                f"Privileged check failed: {e}"
            )
            return {
                "has_privileged": True,
                "privileged_containers": [],
                "error": str(e),
            }

    def check_root_user(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.2 - Check user field on all containers."""
        try:
            containers = task_def.get(
                "containerDefinitions", []
            )
            root_containers = []
            for c in containers:
                user = c.get("user", "")
                # No user set or explicitly root
                if not user or user == "root" or user == "0":
                    root_containers.append(c.get("name", ""))
            return {
                "has_root_user": len(root_containers) > 0,
                "root_containers": root_containers,
            }
        except Exception as e:
            self.logger.warning(f"Root user check failed: {e}")
            return {
                "has_root_user": True,
                "root_containers": [],
                "error": str(e),
            }

    def check_readonly_root_fs(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.3 - Check readonlyRootFilesystem on containers."""
        try:
            containers = task_def.get(
                "containerDefinitions", []
            )
            non_readonly = []
            for c in containers:
                if not c.get("readonlyRootFilesystem", False):
                    non_readonly.append(c.get("name", ""))
            return {
                "all_readonly": len(non_readonly) == 0,
                "non_readonly_containers": non_readonly,
            }
        except Exception as e:
            self.logger.warning(
                f"Read-only root FS check failed: {e}"
            )
            return {
                "all_readonly": False,
                "non_readonly_containers": [],
                "error": str(e),
            }

    def check_linux_capabilities(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.4 - Check Linux capabilities add/drop lists."""
        try:
            containers = task_def.get(
                "containerDefinitions", []
            )
            dangerous_found = set()
            violating_containers = []
            for c in containers:
                linux_params = c.get("linuxParameters", {})
                caps = linux_params.get("capabilities", {})
                added = caps.get("add", [])
                for cap in added:
                    if cap in self.DANGEROUS_CAPABILITIES:
                        dangerous_found.add(cap)
                        if c.get("name", "") not in violating_containers:
                            violating_containers.append(
                                c.get("name", "")
                            )
            return {
                "has_dangerous_caps": len(dangerous_found) > 0,
                "dangerous_caps_found": list(dangerous_found),
                "violating_containers": violating_containers,
            }
        except Exception as e:
            self.logger.warning(
                f"Linux capabilities check failed: {e}"
            )
            return {
                "has_dangerous_caps": True,
                "dangerous_caps_found": [],
                "violating_containers": [],
                "error": str(e),
            }

    def check_network_mode(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.5 - Check networkMode is 'awsvpc'."""
        try:
            mode = task_def.get("networkMode", "bridge")
            return {
                "is_awsvpc": mode == "awsvpc",
                "network_mode": mode,
            }
        except Exception as e:
            self.logger.warning(
                f"Network mode check failed: {e}"
            )
            return {
                "is_awsvpc": False,
                "network_mode": "unknown",
                "error": str(e),
            }

    def check_logging(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.6 - Check logConfiguration on all containers."""
        try:
            containers = task_def.get(
                "containerDefinitions", []
            )
            unlogged = []
            for c in containers:
                log_config = c.get("logConfiguration")
                if not log_config or not log_config.get(
                    "logDriver"
                ):
                    unlogged.append(c.get("name", ""))
            return {
                "all_configured": len(unlogged) == 0,
                "unlogged_containers": unlogged,
            }
        except Exception as e:
            self.logger.warning(f"Logging check failed: {e}")
            return {
                "all_configured": False,
                "unlogged_containers": [],
                "error": str(e),
            }

    def check_secrets_in_env(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.7 - Scan environment variable names AND values
        for secrets (AWS keys, GitHub/Slack tokens, private
        keys, common credential-shaped variable names)."""
        try:
            containers = task_def.get(
                "containerDefinitions", []
            )
            findings = []
            for c in containers:
                env_vars = c.get("environment", [])
                for env in env_vars:
                    name = env.get("name", "")
                    value = env.get("value", "")
                    matched = False
                    # NAME-based heuristics
                    for pattern in self.SECRET_NAME_PATTERNS:
                        if re.match(
                            pattern, name, re.IGNORECASE
                        ):
                            findings.append({
                                "container": c.get(
                                    "name", ""
                                ),
                                "variable": name,
                                "match_type": "name",
                                "pattern": pattern,
                            })
                            matched = True
                            break
                    if matched or not value:
                        continue
                    # VALUE-based heuristics (only if not
                    # already flagged by name to avoid
                    # double-counting the same env var)
                    for pattern, label in (
                        self.SECRET_VALUE_PATTERNS
                    ):
                        if re.search(pattern, value):
                            findings.append({
                                "container": c.get(
                                    "name", ""
                                ),
                                "variable": name,
                                "match_type": "value",
                                "pattern": label,
                            })
                            break
            return {
                "has_plaintext_secrets": len(findings) > 0,
                "findings": findings,
                "finding_count": len(findings),
            }
        except Exception as e:
            self.logger.warning(
                f"Secrets in env check failed: {e}"
            )
            return {
                "has_plaintext_secrets": True,
                "findings": [],
                "finding_count": 0,
                "error": str(e),
            }

    def check_resource_limits(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.8 - Check cpu/memory at task or container level."""
        try:
            # Task-level limits
            task_cpu = task_def.get("cpu")
            task_memory = task_def.get("memory")
            has_task_level = bool(task_cpu and task_memory)

            containers = task_def.get(
                "containerDefinitions", []
            )
            missing_limits = []
            for c in containers:
                cpu = c.get("cpu", 0)
                memory = c.get("memory") or c.get(
                    "memoryReservation"
                )
                if not has_task_level and (not cpu or not memory):
                    missing_limits.append(c.get("name", ""))
            return {
                "all_defined": (
                    has_task_level or len(missing_limits) == 0
                ),
                "has_task_level_limits": has_task_level,
                "missing_limits_containers": missing_limits,
            }
        except Exception as e:
            self.logger.warning(
                f"Resource limits check failed: {e}"
            )
            return {
                "all_defined": False,
                "has_task_level_limits": False,
                "missing_limits_containers": [],
                "error": str(e),
            }

    def check_pid_mode(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.9 - Check pidMode is not 'host'."""
        try:
            pid_mode = task_def.get("pidMode", "")
            return {
                "has_host_pid": pid_mode == "host",
                "pid_mode": pid_mode,
            }
        except Exception as e:
            self.logger.warning(f"PID mode check failed: {e}")
            return {
                "has_host_pid": True,
                "pid_mode": "unknown",
                "error": str(e),
            }

    def check_execution_role(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """B.10 - Check executionRoleArn presence."""
        try:
            role_arn = task_def.get("executionRoleArn")
            return {
                "has_execution_role": bool(role_arn),
                "execution_role_arn": role_arn,
            }
        except Exception as e:
            self.logger.warning(
                f"Execution role check failed: {e}"
            )
            return {
                "has_execution_role": False,
                "execution_role_arn": None,
                "error": str(e),
            }

    def check_all(
        self, task_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run all B.1-B.10 checks on a single task definition."""
        return {
            "privileged": self.check_privileged(task_def),
            "root_user": self.check_root_user(task_def),
            "readonly_root_fs": self.check_readonly_root_fs(
                task_def
            ),
            "linux_capabilities": self.check_linux_capabilities(
                task_def
            ),
            "network_mode": self.check_network_mode(task_def),
            "logging": self.check_logging(task_def),
            "secrets_in_env": self.check_secrets_in_env(task_def),
            "resource_limits": self.check_resource_limits(
                task_def
            ),
            "pid_mode": self.check_pid_mode(task_def),
            "execution_role": self.check_execution_role(task_def),
        }
