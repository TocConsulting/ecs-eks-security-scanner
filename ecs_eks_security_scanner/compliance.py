"""Compliance Engine - 11 frameworks, 128 lambda-based controls.

Evaluates cluster check results against compliance framework controls.
Each control is a lambda that reads from the checks dict built during
scan_cluster(). The checks dict key names are the contract between
checkers and compliance.

Frameworks and control counts:
  AWS-FSBP             16 controls  (11 ECS, 5 EKS)
  CIS Amazon EKS v2.0.0   5 controls  (EKS only)
  EKS-Hardening         5 controls  (EKS only)
  PCI DSS v4.0.1       14 controls  (mixed)
  HIPAA Security Rule  13 controls  (mixed)
  SOC 2                15 controls  (mixed)
  ISO 27001:2022       14 controls  (mixed)
  ISO 27017:2015        7 controls  (mixed)
  ISO 27018:2019        5 controls  (mixed)
  GDPR                 10 controls  (mixed)
  NIST 800-53 Rev 5    24 controls  (mixed)
  ─────────────────────────────────
  Total               128 controls

Disclaimer: mapping ECS/EKS API-layer checks to broad governance
frameworks (HIPAA, GDPR, SOC 2, ISO) is partial technical evidence,
NOT a compliance attestation. CIS Kubernetes Benchmark Section 1 is
N/A on managed EKS; Sections 4-5 (kubelet, RBAC, Pod Security,
NetworkPolicy) need in-cluster access and are out of scope for an
AWS-API-only scanner. Control IDs verified against authoritative
standards - see the research/ folder for sources.
"""

from typing import Dict, Any


# Top-level result keys that scan_ecs_cluster sets but
# scan_eks_cluster does NOT. A compliance lambda touching
# any of these on an EKS cluster is reading data that was
# never populated, so the control is N/A.
# Source: ecs_eks_security_scanner/scanner.py
ECS_ONLY_KEYS = frozenset({
    "container_insights",
    "execute_command_logging",
    "cluster_encryption",
    "capacity_provider_strategy",
    "service_connect_namespace",
    "privileged_containers",
    "root_user_containers",
    "readonly_root_fs",
    "linux_capabilities",
    "network_mode",
    "container_logging",
    "secrets_in_env",
    "resource_limits",
    "pid_mode",
    "execution_role",
    "ecs_exec_enabled",
    "public_ip_assignment",
    "circuit_breaker",
    "fargate_platform_version",
    "service_security_groups",
    "execution_policy_on_task",
    "role_separation",
})

# Top-level result keys that scan_eks_cluster sets but
# scan_ecs_cluster does NOT.
EKS_ONLY_KEYS = frozenset({
    "endpoint_public_access",
    "endpoint_private_access",
    "secrets_encryption",
    "control_plane_logging",
    "kubernetes_version_check",
    "cluster_security_group",
    "managed_addons",
    "fargate_profiles",
    "nodegroup_remote_access",
    "nodegroup_disk_encryption",
    "nodegroup_ami_type",
    "nodegroup_launch_template",
    "oidc_provider",
    "cluster_role_permissions",
})


class _TrackedChecks(dict):
    """dict subclass that records top-level get() keys so
    the compliance evaluator can detect controls that read
    data only populated for the other cluster type."""

    def __init__(self, src: Dict[str, Any]):
        super().__init__(src)
        self.accessed: set = set()

    def get(self, key, default=None):
        self.accessed.add(key)
        return super().get(key, default)


class ComplianceChecker:
    """Evaluate cluster security checks against 11 frameworks."""

    def __init__(self):
        self.frameworks = {}
        self._define_frameworks()

    def _define_frameworks(self):
        """Define all 11 compliance frameworks with controls."""

        self.frameworks = {
            # ========================================================
            # AWS Foundational Security Best Practices
            # (16 controls: 11 ECS + 5 EKS)
            # ECS.1 was retired by AWS Security Hub on
            # 2026-03-04 and is replaced by ECS.4 + ECS.17
            # + ECS.20 (correctly NOT mapped here).
            # Current FSBP ECS controls NOT yet mapped:
            #   ECS.18 - EFS volume in-transit encryption (task-def
            #            volumes[].efsVolumeConfiguration.transitEncryption);
            #            candidate future check (H.4 only covers
            #            Service Connect TLS / load balancers).
            #   ECS.19 - capacity-provider managed termination
            #            protection (niche, ASG-specific).
            #   ECS.21 - Windows container non-admin user (Windows-only).
            # ========================================================
            "AWS-FSBP": {
                "name": (
                    "AWS Foundational Security Best Practices"
                ),
                "controls": {
                    "ECS.2": {
                        "description": (
                            "ECS services should not have"
                            " public IPs auto-assigned"
                        ),
                        "severity": "HIGH",
                        "applies_to": "ecs",
                        "check": lambda r: not r.get(
                            "public_ip_assignment", {}
                        ).get("any_public", True),
                    },
                    "ECS.3": {
                        "description": (
                            "Task definitions should not"
                            " share host process namespace"
                        ),
                        "severity": "HIGH",
                        "applies_to": "ecs",
                        "check": lambda r: not r.get(
                            "pid_mode", {}
                        ).get("has_host_pid", True),
                    },
                    "ECS.4": {
                        "description": (
                            "ECS containers should run"
                            " as non-privileged"
                        ),
                        "severity": "HIGH",
                        "applies_to": "ecs",
                        "check": lambda r: not r.get(
                            "privileged_containers", {}
                        ).get("has_privileged", True),
                    },
                    "ECS.5": {
                        "description": (
                            "ECS containers should use"
                            " read-only root filesystems"
                        ),
                        "severity": "HIGH",
                        "applies_to": "ecs",
                        "check": lambda r: r.get(
                            "readonly_root_fs", {}
                        ).get("all_readonly", False),
                    },
                    "ECS.8": {
                        "description": (
                            "Secrets should not be in"
                            " container environment variables"
                        ),
                        "severity": "HIGH",
                        "applies_to": "ecs",
                        "check": lambda r: not r.get(
                            "secrets_in_env", {}
                        ).get(
                            "has_plaintext_secrets", True
                        ),
                    },
                    "ECS.9": {
                        "description": (
                            "Task definitions should have"
                            " a logging configuration"
                        ),
                        "severity": "HIGH",
                        "applies_to": "ecs",
                        "check": lambda r: r.get(
                            "container_logging", {}
                        ).get("all_configured", False),
                    },
                    "ECS.10": {
                        "description": (
                            "ECS Fargate services should"
                            " run on latest platform version"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "ecs",
                        "check": lambda r: r.get(
                            "fargate_platform_version", {}
                        ).get("all_latest", False),
                    },
                    "ECS.12": {
                        "description": (
                            "ECS clusters should use"
                            " Container Insights"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "ecs",
                        "check": lambda r: r.get(
                            "container_insights", {}
                        ).get("enabled", False),
                    },
                    "ECS.16": {
                        "description": (
                            "ECS task sets should not"
                            " auto-assign public IPs"
                        ),
                        "severity": "HIGH",
                        "applies_to": "ecs",
                        "check": lambda r: not r.get(
                            "public_ip_assignment", {}
                        ).get("any_public", True),
                    },
                    "ECS.17": {
                        "description": (
                            "Task definitions should not"
                            " use host network mode"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "ecs",
                        "check": lambda r: r.get(
                            "network_mode", {}
                        ).get("all_awsvpc", False),
                    },
                    "ECS.20": {
                        "description": (
                            "Task definitions should"
                            " configure non-root users"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "ecs",
                        "check": lambda r: not r.get(
                            "root_user_containers", {}
                        ).get("has_root_user", True),
                    },
                    "EKS.1": {
                        "description": (
                            "EKS cluster endpoints should"
                            " not be publicly accessible"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: not r.get(
                            "endpoint_public_access", {}
                        ).get("unrestricted", True),
                    },
                    "EKS.2": {
                        "description": (
                            "EKS clusters should run on a"
                            " supported Kubernetes version"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "kubernetes_version_check", {}
                        ).get("supported", False),
                    },
                    # NOTE: FSBP EKS.3 is scheduled to retire after
                    # 2026-08-10 (KMS secrets encryption is default
                    # since Kubernetes 1.28). Still active until then;
                    # the secrets_encryption check stays native (D.3).
                    "EKS.3": {
                        "description": (
                            "EKS clusters should use"
                            " encrypted Kubernetes secrets"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "secrets_encryption", {}
                        ).get("enabled", False),
                    },
                    "EKS.8": {
                        "description": (
                            "EKS clusters should have"
                            " audit logging enabled"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "control_plane_logging", {}
                        ).get("all_enabled", False),
                    },
                    "EKS.9": {
                        "description": (
                            "EKS node groups should run on a"
                            " supported Kubernetes version"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        # Node groups inherit the cluster's
                        # Kubernetes version by default, so
                        # the cluster-level supported check
                        # is a reliable proxy. Source:
                        # https://docs.aws.amazon.com/
                        #   securityhub/latest/userguide/
                        #   eks-controls.html#eks-9
                        "check": lambda r: r.get(
                            "kubernetes_version_check", {}
                        ).get("supported", False),
                    },
                },
            },
            # ========================================================
            # CIS Amazon EKS Benchmark v2.0.0 (5 controls)
            # (v1.5 was stale; v2.0.0 is current as of 2026. The
            #  control SECTIONS are stable across versions - logging
            #  §2, image scan §5.1, KMS secrets §5.3, endpoint §5.4;
            #  confirm exact leaf numbers vs the licensed v2.0.0 PDF.)
            #
            # Only the controls that map cleanly to public
            # AWS-API signals are implemented. Kubelet/RBAC/
            # admission-controller checks (CIS 3.1.x, 3.2.x,
            # 4.x) require in-cluster inspection and are out
            # of scope for an API-only scanner. Source:
            # https://www.cisecurity.org/benchmark/kubernetes
            # ========================================================
            "CIS-EKS-v2.0": {
                "name": (
                    "CIS Amazon EKS Benchmark v2.0.0"
                ),
                "controls": {
                    "2.1.1": {
                        "description": (
                            "Enable audit logging"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "control_plane_logging", {}
                        ).get("all_enabled", False),
                    },
                    "5.1.1": {
                        "description": (
                            "Ensure image scanning"
                            " is enabled"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "ecr_scan_on_push", {}
                        ).get("all_enabled", False),
                    },
                    "5.3.1": {
                        "description": (
                            "Encrypt Kubernetes secrets"
                            " with KMS"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "secrets_encryption", {}
                        ).get("enabled", False),
                    },
                    "5.4.1": {
                        "description": (
                            "Restrict public access"
                            " to cluster API server"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "eks",
                        "check": lambda r: not r.get(
                            "endpoint_public_access", {}
                        ).get("unrestricted", True),
                    },
                    "5.4.2": {
                        "description": (
                            "Ensure private endpoint"
                            " access is enabled"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "endpoint_private_access", {}
                        ).get("enabled", False),
                    },
                },
            },
            # ========================================================
            # EKS-Hardening (5 controls)
            #
            # AWS-specific EKS node hardening checks that
            # don't appear in any CIS Kubernetes Benchmark
            # version. Previously mis-numbered as CIS
            # sections 3.1.1/3.2.1/3.2.2/4.1.1/4.2.1 - those
            # CIS sections refer to kubeconfig file perms,
            # kubelet anonymous-auth, kubelet authorization
            # mode, cluster-admin RBAC, and privileged
            # container admission. None of which this tool
            # actually checks. Renamed here to custom IDs to
            # avoid false claims of CIS conformance.
            # ========================================================
            "EKS-Hardening": {
                "name": "AWS EKS Node Hardening",
                "controls": {
                    "NODE.SSH": {
                        "description": (
                            "Restrict SSH access to"
                            " EKS node groups"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: not r.get(
                            "nodegroup_remote_access", {}
                        ).get("any_unrestricted", True),
                    },
                    "NODE.AMI": {
                        "description": (
                            "Use AWS-supported AMI types"
                            " (AL2023 or Bottlerocket)"
                            " for node groups"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "nodegroup_ami_type", {}
                        ).get("all_secure", False),
                    },
                    "NODE.DISK": {
                        "description": (
                            "EKS node group EBS volumes"
                            " should be encrypted"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "nodegroup_disk_encryption", {}
                        ).get("all_encrypted", False),
                    },
                    "IAM.IRSA": {
                        "description": (
                            "Configure an IAM OIDC"
                            " identity provider on the"
                            " cluster (enables IRSA)"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "oidc_provider", {}
                        ).get("configured", False),
                    },
                    "IAM.ROLE": {
                        "description": (
                            "EKS cluster IAM role should"
                            " not have admin or wildcard"
                            " policies"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "eks",
                        "check": lambda r: not r.get(
                            "cluster_role_permissions", {}
                        ).get(
                            "overly_permissive", True
                        ),
                    },
                },
            },
            # ========================================================
            # PCI DSS v4.0.1 (14 controls)
            # ========================================================
            "PCI-DSS-v4.0.1": {
                "name": "PCI DSS v4.0.1",
                "controls": {
                    "1.2.1": {
                        "description": (
                            "Restrict inbound and outbound"
                            " network traffic"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "service_security_groups", {}
                            ).get("all_configured", False)
                            and not r.get(
                                "nodegroup_remote_access", {}
                            ).get(
                                "any_unrestricted", True
                            )
                        ),
                    },
                    "1.3.1": {
                        "description": (
                            "Inbound traffic restricted"
                            " to cardholder data env"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "endpoint_public_access", {}
                            ).get("unrestricted", True)
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                        ),
                    },
                    "1.3.2": {
                        "description": (
                            "Outbound traffic restricted"
                            " from cardholder data env"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "vpc_flow_logs", {}
                        ).get("enabled", False),
                    },
                    "2.2.1": {
                        "description": (
                            "Secure container"
                            " configurations"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "privileged_containers", {}
                            ).get("has_privileged", True)
                            and r.get(
                                "readonly_root_fs", {}
                            ).get("all_readonly", False)
                            and not r.get(
                                "linux_capabilities", {}
                            ).get(
                                "has_dangerous_caps", True
                            )
                            and r.get(
                                "network_mode", {}
                            ).get("all_awsvpc", False)
                            and not r.get(
                                "pid_mode", {}
                            ).get("has_host_pid", True)
                        ),
                    },
                    "2.2.7": {
                        "description": (
                            "Non-console admin access"
                            " encrypted"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "endpoint_private_access", {}
                            ).get("enabled", False)
                            and r.get(
                                "in_transit_encryption", {}
                            ).get("configured", False)
                        ),
                    },
                    "3.4.1": {
                        "description": (
                            "PAN rendered unreadable"
                            " via encryption at rest"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "secrets_encryption", {}
                            ).get("enabled", False)
                            or r.get(
                                "cluster_encryption", {}
                            ).get("kms_enabled", False)
                        ),
                    },
                    "6.3.3": {
                        "description": (
                            "Patch vulnerabilities"
                            " promptly"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "kubernetes_version_check", {}
                        ).get("supported", False),
                    },
                    "7.2.1": {
                        "description": (
                            "Appropriate access control"
                            " via least privilege"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "both",
                        "check": lambda r: not r.get(
                            "overly_permissive_roles", {}
                        ).get("has_admin_roles", True),
                    },
                    "8.3.1": {
                        "description": (
                            "All user IDs and"
                            " authentication managed"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "oidc_provider", {}
                            ).get("configured", False)
                            and r.get(
                                "role_separation", {}
                            ).get("separated", False)
                        ),
                    },
                    "8.6.1": {
                        "description": (
                            "System and service account"
                            " management"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "role_separation", {}
                            ).get("separated", False)
                            and not r.get(
                                "execution_policy_on_task",
                                {},
                            ).get("has_violation", True)
                        ),
                    },
                    "10.2.1": {
                        "description": (
                            "Audit logs enabled for"
                            " all components"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "control_plane_logging", {}
                            ).get("all_enabled", False)
                            or (
                                r.get(
                                    "container_logging", {}
                                ).get(
                                    "all_configured", False
                                )
                                and r.get(
                                    "execute_command_logging",
                                    {},
                                ).get("configured", False)
                            )
                        ),
                    },
                    "10.3.1": {
                        "description": (
                            "Protect audit logs from"
                            " modification"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "execute_command_logging", {}
                        ).get("configured", False),
                    },
                    "11.3.1": {
                        "description": (
                            "Vulnerability scanning"
                            " performed regularly"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "ecr_scan_on_push", {}
                        ).get("all_enabled", False),
                    },
                    "11.5.1": {
                        "description": (
                            "Intrusion detection via"
                            " GuardDuty"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "guardduty_enabled", {}
                        ).get("enabled", False),
                    },
                },
            },
            # ========================================================
            # HIPAA (13 controls)
            # ========================================================
            "HIPAA": {
                "name": (
                    "HIPAA Security Rule (45 CFR Part 164)"
                ),
                "controls": {
                    "164.312(a)(1)": {
                        "description": (
                            "Access control mechanisms"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and r.get(
                                "oidc_provider", {}
                            ).get("configured", False)
                        ),
                    },
                    "164.312(a)(2)(i)": {
                        "description": (
                            "Unique user identification"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "role_separation", {}
                        ).get("separated", False),
                    },
                    "164.312(a)(2)(iv)": {
                        "description": (
                            "Encryption and decryption"
                            " of ePHI"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "secrets_encryption", {}
                            ).get("enabled", False)
                            or r.get(
                                "cluster_encryption", {}
                            ).get("kms_enabled", False)
                        ),
                    },
                    "164.312(b)": {
                        "description": (
                            "Audit controls for ePHI"
                            " access"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "control_plane_logging",
                                    {},
                                ).get("all_enabled", False)
                                or r.get(
                                    "container_logging", {}
                                ).get(
                                    "all_configured", False
                                )
                            )
                            and r.get(
                                "execute_command_logging", {}
                            ).get("configured", False)
                        ),
                    },
                    "164.312(c)(1)": {
                        "description": (
                            "Integrity controls for ePHI"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "readonly_root_fs", {}
                            ).get("all_readonly", False)
                            and r.get(
                                "ecr_tag_immutability", {}
                            ).get("all_immutable", False)
                        ),
                    },
                    "164.312(e)(2)(i)": {
                        # The HIPAA section that addresses
                        # in-transit protection is
                        # §164.312(e)(2)(i) "Integrity
                        # controls" under (e) Transmission
                        # Security. §164.312(c)(2) is
                        # "Mechanism to authenticate ePHI"
                        # and is implemented separately
                        # below.
                        "description": (
                            "Integrity controls: protect"
                            " ePHI from improper alteration"
                            " or destruction during"
                            " transmission"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "in_transit_encryption", {}
                        ).get("configured", False),
                    },
                    "164.312(c)(2)": {
                        "description": (
                            "Mechanism to authenticate"
                            " electronic protected health"
                            " information (ECR tag"
                            " immutability ensures image"
                            " content cannot be altered"
                            " in place)"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "ecr_tag_immutability", {}
                        ).get("all_immutable", False),
                    },
                    "164.312(d)": {
                        "description": (
                            "Person or entity"
                            " authentication"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "oidc_provider", {}
                        ).get("configured", False),
                    },
                    "164.312(e)(1)": {
                        "description": (
                            "Transmission security"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "endpoint_private_access", {}
                            ).get("enabled", False)
                            and r.get(
                                "in_transit_encryption", {}
                            ).get("configured", False)
                        ),
                    },
                    "164.312(e)(2)(ii)": {
                        "description": (
                            "Encryption in transit"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "in_transit_encryption", {}
                        ).get("configured", False),
                    },
                    "164.308(a)(1)(ii)(D)": {
                        "description": (
                            "Information system activity"
                            " review"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                            and r.get(
                                "vpc_flow_logs", {}
                            ).get("enabled", False)
                        ),
                    },
                    "164.308(a)(3)": {
                        "description": (
                            "Workforce security and"
                            " least privilege"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and not r.get(
                                "execution_policy_on_task",
                                {},
                            ).get("has_violation", True)
                        ),
                    },
                    "164.308(a)(5)(ii)(B)": {
                        "description": (
                            "Protection from malicious"
                            " software"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "ecr_scan_on_push", {}
                            ).get("all_enabled", False)
                            and r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                        ),
                    },
                },
            },
            # ========================================================
            # SOC 2 (15 controls)
            # ========================================================
            "SOC2": {
                "name": (
                    "SOC 2 (Trust Services Criteria 2017,"
                    " Revised Points of Focus 2022)"
                ),
                "controls": {
                    "CC6.1": {
                        "description": (
                            "Logical access security"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and r.get(
                                "oidc_provider", {}
                            ).get("configured", False)
                            and not r.get(
                                "endpoint_public_access", {}
                            ).get("unrestricted", True)
                        ),
                    },
                    "CC6.2": {
                        "description": (
                            "Access credentials"
                            " management"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "role_separation", {}
                            ).get("separated", False)
                            and not r.get(
                                "secrets_in_env", {}
                            ).get(
                                "has_plaintext_secrets",
                                True,
                            )
                            and r.get(
                                "execution_role", {}
                            ).get("all_configured", False)
                        ),
                    },
                    "CC6.3": {
                        "description": (
                            "Access authorization via"
                            " least privilege"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and not r.get(
                                "execution_policy_on_task",
                                {},
                            ).get("has_violation", True)
                            and not r.get(
                                "cluster_role_permissions",
                                {},
                            ).get(
                                "overly_permissive", True
                            )
                        ),
                    },
                    "CC6.6": {
                        "description": (
                            "Security measures against"
                            " threats"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                            and r.get(
                                "ecr_scan_on_push", {}
                            ).get("all_enabled", False)
                        ),
                    },
                    "CC6.7": {
                        "description": (
                            "Restrict transmission"
                            " of data"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "endpoint_private_access", {}
                            ).get("enabled", False)
                            and r.get(
                                "in_transit_encryption", {}
                            ).get("configured", False)
                        ),
                    },
                    "CC6.8": {
                        "description": (
                            "Prevent unauthorized"
                            " software execution"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "privileged_containers", {}
                            ).get("has_privileged", True)
                            and r.get(
                                "readonly_root_fs", {}
                            ).get("all_readonly", False)
                        ),
                    },
                    "CC7.1": {
                        "description": (
                            "Detection of security"
                            " events"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                            and (
                                r.get(
                                    "control_plane_logging",
                                    {},
                                ).get(
                                    "all_enabled", False
                                )
                                or r.get(
                                    "vpc_flow_logs", {}
                                ).get("enabled", False)
                            )
                        ),
                    },
                    "CC7.2": {
                        "description": (
                            "Monitoring of security"
                            " events"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "container_insights", {}
                            ).get("enabled", False)
                            and r.get(
                                "vpc_flow_logs", {}
                            ).get("enabled", False)
                        ),
                    },
                    "CC7.3": {
                        "description": (
                            "Evaluation of security"
                            " events"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "execute_command_logging", {}
                            ).get("configured", False)
                            and r.get(
                                "container_logging", {}
                            ).get("all_configured", False)
                        ),
                    },
                    "CC8.1": {
                        "description": (
                            "Change management controls"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "circuit_breaker", {}
                            ).get("all_enabled", False)
                            and r.get(
                                "managed_addons", {}
                            ).get("all_present", False)
                        ),
                    },
                    "A1.2": {
                        "description": (
                            "System availability and"
                            " capacity planning"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "resource_limits", {}
                            ).get("all_defined", False)
                            and r.get(
                                "capacity_provider_strategy",
                                {},
                            ).get("has_strategy", False)
                        ),
                    },
                    "C1.1": {
                        "description": (
                            "Confidentiality via"
                            " encryption"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "secrets_encryption", {}
                                ).get("enabled", False)
                                or r.get(
                                    "cluster_encryption", {}
                                ).get("kms_enabled", False)
                            )
                            and not r.get(
                                "secrets_in_env", {}
                            ).get(
                                "has_plaintext_secrets",
                                True,
                            )
                        ),
                    },
                    "C1.2": {
                        "description": (
                            "Confidentiality disposal"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "ecr_tag_immutability", {}
                        ).get("all_immutable", False),
                    },
                    "P6.1": {
                        "description": (
                            "Privacy and data protection"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "secrets_in_env", {}
                            ).get(
                                "has_plaintext_secrets",
                                True,
                            )
                            and not r.get(
                                "ecs_exec_enabled", {}
                            ).get("any_enabled", False)
                        ),
                    },
                    "P6.5": {
                        "description": (
                            "Privacy access limitation"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                        ),
                    },
                },
            },
            # ========================================================
            # ISO 27001:2022 (14 controls)
            # ========================================================
            "ISO27001": {
                "name": "ISO 27001:2022",
                "controls": {
                    "A.5.15": {
                        "description": (
                            "Access control policy"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and r.get(
                                "oidc_provider", {}
                            ).get("configured", False)
                        ),
                    },
                    "A.5.18": {
                        "description": (
                            "Access rights and least"
                            " privilege"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "role_separation", {}
                            ).get("separated", False)
                            and not r.get(
                                "execution_policy_on_task",
                                {},
                            ).get("has_violation", True)
                        ),
                    },
                    "A.5.23": {
                        "description": (
                            "Cloud services security"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "endpoint_public_access", {}
                            ).get("unrestricted", True)
                            and r.get(
                                "endpoint_private_access", {}
                            ).get("enabled", False)
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                        ),
                    },
                    "A.8.1": {
                        "description": (
                            "User endpoint devices"
                            " and node security"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: (
                            not r.get(
                                "nodegroup_remote_access", {}
                            ).get("any_unrestricted", True)
                            and r.get(
                                "nodegroup_disk_encryption",
                                {},
                            ).get("all_encrypted", False)
                            and r.get(
                                "nodegroup_launch_template",
                                {},
                            ).get("all_use_template", False)
                        ),
                    },
                    "A.8.5": {
                        "description": (
                            "Secure authentication"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: (
                            r.get(
                                "oidc_provider", {}
                            ).get("configured", False)
                            and r.get(
                                "fargate_profiles", {}
                            ).get(
                                "private_subnets_only", False
                            )
                        ),
                    },
                    "A.8.9": {
                        "description": (
                            "Configuration management"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "privileged_containers", {}
                            ).get("has_privileged", True)
                            and r.get(
                                "readonly_root_fs", {}
                            ).get("all_readonly", False)
                            and r.get(
                                "network_mode", {}
                            ).get("all_awsvpc", False)
                            and not r.get(
                                "pid_mode", {}
                            ).get("has_host_pid", True)
                        ),
                    },
                    "A.8.10": {
                        "description": (
                            "Information deletion"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "ecr_tag_immutability", {}
                        ).get("all_immutable", False),
                    },
                    "A.8.12": {
                        "description": (
                            "Data leakage prevention"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "secrets_in_env", {}
                            ).get(
                                "has_plaintext_secrets",
                                True,
                            )
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                        ),
                    },
                    "A.8.15": {
                        "description": (
                            "Logging and monitoring"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "control_plane_logging",
                                    {},
                                ).get(
                                    "all_enabled", False
                                )
                                or r.get(
                                    "container_logging", {}
                                ).get(
                                    "all_configured", False
                                )
                            )
                            and r.get(
                                "execute_command_logging", {}
                            ).get("configured", False)
                        ),
                    },
                    "A.8.16": {
                        "description": (
                            "Monitoring activities"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                            and r.get(
                                "container_insights", {}
                            ).get("enabled", False)
                        ),
                    },
                    "A.8.20": {
                        "description": (
                            "Network security controls"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "service_security_groups", {}
                            ).get("all_configured", False)
                            and r.get(
                                "vpc_flow_logs", {}
                            ).get("enabled", False)
                        ),
                    },
                    "A.8.24": {
                        "description": (
                            "Use of cryptography"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "secrets_encryption", {}
                            ).get("enabled", False)
                            or r.get(
                                "cluster_encryption", {}
                            ).get("kms_enabled", False)
                        ),
                    },
                    "A.8.25": {
                        "description": (
                            "Secure development"
                            " lifecycle"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "ecr_scan_on_push", {}
                            ).get("all_enabled", False)
                            and r.get(
                                "circuit_breaker", {}
                            ).get("all_enabled", False)
                        ),
                    },
                    "A.8.28": {
                        "description": (
                            "Secure coding practices"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "linux_capabilities", {}
                            ).get(
                                "has_dangerous_caps", True
                            )
                            and not r.get(
                                "pid_mode", {}
                            ).get("has_host_pid", True)
                        ),
                    },
                },
            },
            # ========================================================
            # ISO 27017:2015 (7 controls)
            # ========================================================
            "ISO27017": {
                "name": "ISO 27017:2015",
                "controls": {
                    "CLD.6.3.1": {
                        "description": (
                            "Shared roles and"
                            " responsibilities"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "role_separation", {}
                        ).get("separated", False),
                    },
                    "CLD.9.5.1": {
                        "description": (
                            "Segregation in cloud"
                            " computing"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "network_mode", {}
                            ).get("all_awsvpc", False)
                            and not r.get(
                                "pid_mode", {}
                            ).get("has_host_pid", True)
                        ),
                    },
                    "CLD.9.5.2": {
                        "description": (
                            "Virtual machine hardening"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "privileged_containers", {}
                            ).get("has_privileged", True)
                            and r.get(
                                "readonly_root_fs", {}
                            ).get("all_readonly", False)
                        ),
                    },
                    "CLD.12.4.1": {
                        # Was incorrectly numbered CLD.12.1.5
                        # (which is Administrator's
                        # operational security). The real
                        # event-logging control is CLD.12.4.1
                        # under 12.4 Logging and monitoring.
                        "description": (
                            "Event logging: capture workload"
                            " and control-plane events for"
                            " security review"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "container_insights", {}
                            ).get("enabled", False)
                            and r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                        ),
                    },
                    "CLD.12.4.5": {
                        "description": (
                            "Monitoring of cloud services:"
                            " audit logs of control-plane"
                            " and administrative actions"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "control_plane_logging", {}
                            ).get("all_enabled", False)
                            or r.get(
                                "execute_command_logging", {}
                            ).get("configured", False)
                        ),
                    },
                    "CLD.13.1.4": {
                        "description": (
                            "Container network security"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "service_security_groups", {}
                            ).get("all_configured", False)
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                            and r.get(
                                "cluster_security_group", {}
                            ).get("configured", False)
                        ),
                    },
                    "CLD.8.1.5": {
                        "description": (
                            "Removal of cloud service"
                            " assets"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "ecr_tag_immutability", {}
                        ).get("all_immutable", False),
                    },
                },
            },
            # ========================================================
            # ISO 27018:2019 (5 controls)
            # ========================================================
            "ISO27018": {
                "name": (
                    "ISO 27018:2019 (PII in public cloud;"
                    " superseded by ISO 27018:2025 - see"
                    " v1.1 migration notes)"
                ),
                "controls": {
                    "A.2.1": {
                        "description": (
                            "Purpose limitation and"
                            " data handling"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "secrets_in_env", {}
                            ).get(
                                "has_plaintext_secrets",
                                True,
                            )
                            and not r.get(
                                "ecs_exec_enabled", {}
                            ).get("any_enabled", False)
                        ),
                    },
                    "A.7.1": {
                        "description": (
                            "Data minimization"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "resource_limits", {}
                            ).get("all_defined", False)
                            and not r.get(
                                "linux_capabilities", {}
                            ).get(
                                "has_dangerous_caps", True
                            )
                        ),
                    },
                    "A.10.1": {
                        "description": (
                            "Cryptographic controls"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "secrets_encryption", {}
                                ).get("enabled", False)
                                or r.get(
                                    "cluster_encryption", {}
                                ).get("kms_enabled", False)
                            )
                            and r.get(
                                "in_transit_encryption", {}
                            ).get("configured", False)
                        ),
                    },
                    "A.11.1": {
                        "description": (
                            "Equipment security and"
                            " node hardening"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: (
                            not r.get(
                                "nodegroup_remote_access", {}
                            ).get("any_unrestricted", True)
                            and r.get(
                                "nodegroup_disk_encryption",
                                {},
                            ).get("all_encrypted", False)
                        ),
                    },
                    "A.12.4": {
                        "description": (
                            "Logging and monitoring"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "control_plane_logging",
                                    {},
                                ).get(
                                    "all_enabled", False
                                )
                                or r.get(
                                    "container_logging", {}
                                ).get(
                                    "all_configured", False
                                )
                            )
                        ),
                    },
                },
            },
            # ========================================================
            # GDPR (10 controls)
            # ========================================================
            "GDPR": {
                "name": (
                    "General Data Protection Regulation"
                    " (EU) 2016/679"
                ),
                "controls": {
                    "Art.5(1)(f)": {
                        "description": (
                            "Integrity and"
                            " confidentiality"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "secrets_encryption", {}
                                ).get("enabled", False)
                                or r.get(
                                    "cluster_encryption", {}
                                ).get("kms_enabled", False)
                            )
                            and r.get(
                                "in_transit_encryption", {}
                            ).get("configured", False)
                        ),
                    },
                    "Art.25": {
                        "description": (
                            "Data protection by design"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "secrets_in_env", {}
                            ).get(
                                "has_plaintext_secrets",
                                True,
                            )
                            and r.get(
                                "readonly_root_fs", {}
                            ).get("all_readonly", False)
                            and not r.get(
                                "privileged_containers", {}
                            ).get("has_privileged", True)
                        ),
                    },
                    "Art.30": {
                        "description": (
                            "Records of processing"
                            " activities via audit logs"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "control_plane_logging",
                                    {},
                                ).get(
                                    "all_enabled", False
                                )
                                or r.get(
                                    "container_logging", {}
                                ).get(
                                    "all_configured", False
                                )
                            )
                            and r.get(
                                "execute_command_logging", {}
                            ).get("configured", False)
                        ),
                    },
                    "Art.32(1)(a)": {
                        "description": (
                            "Encryption of personal data"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "secrets_encryption", {}
                            ).get("enabled", False)
                            or r.get(
                                "cluster_encryption", {}
                            ).get("kms_enabled", False)
                        ),
                    },
                    "Art.32(1)(b)": {
                        "description": (
                            "Ongoing confidentiality"
                            " of processing"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                            and not r.get(
                                "endpoint_public_access", {}
                            ).get("unrestricted", True)
                        ),
                    },
                    "Art.32(1)(c)": {
                        "description": (
                            "Ability to restore"
                            " availability"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "circuit_breaker", {}
                            ).get("all_enabled", False)
                            and r.get(
                                "capacity_provider_strategy",
                                {},
                            ).get("has_strategy", False)
                        ),
                    },
                    "Art.32(1)(d)": {
                        "description": (
                            "Regular testing and"
                            " evaluation"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "ecr_scan_on_push", {}
                            ).get("all_enabled", False)
                            and r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                        ),
                    },
                    "Art.33": {
                        "description": (
                            "Notification of data breach"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                            and (
                                r.get(
                                    "control_plane_logging",
                                    {},
                                ).get(
                                    "all_enabled", False
                                )
                                or r.get(
                                    "container_insights", {}
                                ).get("enabled", False)
                            )
                        ),
                    },
                    "Art.35": {
                        "description": (
                            "Data protection impact"
                            " assessment"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "secrets_in_env", {}
                            ).get(
                                "has_plaintext_secrets",
                                True,
                            )
                            and not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                        ),
                    },
                    "Art.5(1)(e)": {
                        "description": (
                            "Storage limitation"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "ecr_tag_immutability", {}
                        ).get("all_immutable", False),
                    },
                },
            },
            # ========================================================
            # NIST 800-53 Rev 5 (24 controls)
            # ========================================================
            "NIST-800-53": {
                "name": (
                    "NIST SP 800-53 Rev. 5 Release 5.2.0"
                ),
                "controls": {
                    "AC-2": {
                        "description": (
                            "Account management"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "role_separation", {}
                            ).get("separated", False)
                            and r.get(
                                "oidc_provider", {}
                            ).get("configured", False)
                        ),
                    },
                    "AC-3": {
                        "description": (
                            "Access enforcement"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and not r.get(
                                "endpoint_public_access", {}
                            ).get("unrestricted", True)
                        ),
                    },
                    "AC-4": {
                        "description": (
                            "Information flow"
                            " enforcement"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "service_security_groups", {}
                            ).get("all_configured", False)
                            and r.get(
                                "vpc_flow_logs", {}
                            ).get("enabled", False)
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                            and r.get(
                                "cluster_security_group", {}
                            ).get("configured", False)
                        ),
                    },
                    "AC-6": {
                        "description": (
                            "Least privilege"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "overly_permissive_roles", {}
                            ).get("has_admin_roles", True)
                            and not r.get(
                                "execution_policy_on_task",
                                {},
                            ).get("has_violation", True)
                            and not r.get(
                                "cluster_role_permissions",
                                {},
                            ).get(
                                "overly_permissive", True
                            )
                        ),
                    },
                    "AC-17": {
                        "description": (
                            "Remote access control"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "endpoint_public_access", {}
                            ).get("unrestricted", True)
                            and r.get(
                                "endpoint_private_access", {}
                            ).get("enabled", False)
                            and not r.get(
                                "nodegroup_remote_access", {}
                            ).get("any_unrestricted", True)
                        ),
                    },
                    "AU-2": {
                        "description": (
                            "Event logging"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "control_plane_logging",
                                {},
                            ).get(
                                "all_enabled", False
                            )
                            or r.get(
                                "container_logging", {}
                            ).get(
                                "all_configured", False
                            )
                        ),
                    },
                    "AU-3": {
                        "description": (
                            "Content of audit records"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "execute_command_logging", {}
                        ).get("configured", False),
                    },
                    "AU-6": {
                        "description": (
                            "Audit log review and"
                            " analysis"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "guardduty_enabled", {}
                        ).get("enabled", False),
                    },
                    "AU-12": {
                        "description": (
                            "Audit record generation"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "control_plane_logging",
                                    {},
                                ).get(
                                    "all_enabled", False
                                )
                                or r.get(
                                    "container_logging", {}
                                ).get(
                                    "all_configured", False
                                )
                            )
                            and r.get(
                                "execute_command_logging", {}
                            ).get("configured", False)
                        ),
                    },
                    "CA-7": {
                        "description": (
                            "Continuous monitoring"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "container_insights", {}
                            ).get("enabled", False)
                            and r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                        ),
                    },
                    "CM-2": {
                        "description": (
                            "Baseline configuration"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "network_mode", {}
                            ).get("all_awsvpc", False)
                            and not r.get(
                                "privileged_containers", {}
                            ).get("has_privileged", True)
                            and r.get(
                                "readonly_root_fs", {}
                            ).get("all_readonly", False)
                            and r.get(
                                "resource_limits", {}
                            ).get("all_defined", False)
                        ),
                    },
                    "CM-6": {
                        "description": (
                            "Configuration settings"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "linux_capabilities", {}
                            ).get(
                                "has_dangerous_caps", True
                            )
                            and not r.get(
                                "pid_mode", {}
                            ).get("has_host_pid", True)
                            and r.get(
                                "execution_role", {}
                            ).get("all_configured", False)
                        ),
                    },
                    "CM-7": {
                        "description": (
                            "Least functionality"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "privileged_containers", {}
                            ).get("has_privileged", True)
                            and not r.get(
                                "linux_capabilities", {}
                            ).get(
                                "has_dangerous_caps", True
                            )
                        ),
                    },
                    "CP-9": {
                        "description": (
                            "System backup and recovery"
                        ),
                        "severity": "MEDIUM",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "circuit_breaker", {}
                        ).get("all_enabled", False),
                    },
                    "IA-2": {
                        "description": (
                            "Identification and"
                            " authentication"
                        ),
                        "severity": "HIGH",
                        "applies_to": "eks",
                        "check": lambda r: r.get(
                            "oidc_provider", {}
                        ).get("configured", False),
                    },
                    "IA-5": {
                        "description": (
                            "Authenticator management"
                        ),
                        "severity": "CRITICAL",
                        "applies_to": "both",
                        "check": lambda r: not r.get(
                            "secrets_in_env", {}
                        ).get(
                            "has_plaintext_secrets", True
                        ),
                    },
                    "IR-4": {
                        "description": (
                            "Incident handling"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: r.get(
                            "guardduty_enabled", {}
                        ).get("enabled", False),
                    },
                    "RA-5": {
                        "description": (
                            "Vulnerability monitoring"
                            " and scanning"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "ecr_scan_on_push", {}
                            ).get("all_enabled", False)
                            and r.get(
                                "kubernetes_version_check",
                                {},
                            ).get("supported", False)
                        ),
                    },
                    "SC-7": {
                        "description": (
                            "Boundary protection"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            not r.get(
                                "endpoint_public_access", {}
                            ).get("unrestricted", True)
                            and not r.get(
                                "public_ip_assignment", {}
                            ).get("any_public", True)
                            and r.get(
                                "service_security_groups", {}
                            ).get("all_configured", False)
                            and r.get(
                                "cluster_security_group", {}
                            ).get("configured", False)
                        ),
                    },
                    "SC-8": {
                        "description": (
                            "Transmission"
                            " confidentiality"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "in_transit_encryption", {}
                            ).get("configured", False)
                            and r.get(
                                "endpoint_private_access", {}
                            ).get("enabled", False)
                        ),
                    },
                    "SC-13": {
                        "description": (
                            "Cryptographic protection"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "secrets_encryption", {}
                            ).get("enabled", False)
                            or r.get(
                                "cluster_encryption", {}
                            ).get("kms_enabled", False)
                        ),
                    },
                    "SC-28": {
                        "description": (
                            "Protection of information"
                            " at rest"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            (
                                r.get(
                                    "secrets_encryption", {}
                                ).get("enabled", False)
                                or r.get(
                                    "cluster_encryption", {}
                                ).get("kms_enabled", False)
                            )
                            and r.get(
                                "nodegroup_disk_encryption",
                                {},
                            ).get("all_encrypted", False)
                        ),
                    },
                    "SI-2": {
                        "description": (
                            "Flaw remediation"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "kubernetes_version_check",
                                {},
                            ).get("supported", False)
                            and r.get(
                                "managed_addons", {}
                            ).get("all_present", False)
                        ),
                    },
                    "SI-4": {
                        "description": (
                            "System monitoring"
                        ),
                        "severity": "HIGH",
                        "applies_to": "both",
                        "check": lambda r: (
                            r.get(
                                "guardduty_enabled", {}
                            ).get("enabled", False)
                            and r.get(
                                "container_insights", {}
                            ).get("enabled", False)
                        ),
                    },
                },
            },
        }

    def check_cluster_compliance(
        self,
        checks: Dict[str, Any],
        cluster_type: str,
    ) -> Dict[str, Dict[str, Any]]:
        """Evaluate all frameworks against cluster check results.

        Args:
            checks: The checks dict from scan_cluster
            cluster_type: Either "ecs" or "eks"

        Returns:
            Dict mapping framework ID to compliance results
        """
        compliance = {}
        for fw_id, framework in self.frameworks.items():
            compliance[fw_id] = (
                self._check_framework_compliance(
                    checks, fw_id, framework, cluster_type
                )
            )
        return compliance

    def _check_framework_compliance(
        self,
        checks: Dict[str, Any],
        framework_id: str,
        framework: Dict[str, Any],
        cluster_type: str,
    ) -> Dict[str, Any]:
        """Evaluate one framework against cluster checks.

        Skips controls where applies_to does not match
        the cluster_type.

        Returns:
            Dict with passed/failed/skipped controls,
            percentage, compliance status
        """
        controls = framework.get("controls", {})
        passed = []
        failed = []
        skipped = []

        foreign_keys = (
            EKS_ONLY_KEYS if cluster_type == "ecs"
            else ECS_ONLY_KEYS if cluster_type == "eks"
            else frozenset()
        )

        for control_id, control in controls.items():
            applies_to = control.get("applies_to", "both")
            if (
                applies_to != "both"
                and applies_to != cluster_type
            ):
                skipped.append({
                    "control_id": control_id,
                    "description": control["description"],
                    "reason": (
                        "not applicable to "
                        f"{cluster_type}"
                    ),
                })
                continue

            tracked = _TrackedChecks(checks)
            try:
                result = control["check"](tracked)
            except Exception as e:
                # If lambda fails, treat as failed
                failed.append({
                    "control_id": control_id,
                    "description": control["description"],
                    "severity": control.get(
                        "severity", "MEDIUM"
                    ),
                })
                continue

            # A "both"-tagged control that reads a key
            # only set by the other service was never
            # going to evaluate meaningfully on this
            # cluster type. Skip rather than report a
            # spurious FAIL from the fail-closed default.
            if applies_to == "both":
                used_foreign = (
                    tracked.accessed & foreign_keys
                )
                if used_foreign:
                    skipped.append({
                        "control_id": control_id,
                        "description": (
                            control["description"]
                        ),
                        "reason": (
                            "not applicable to "
                            f"{cluster_type} (control"
                            " evaluates keys "
                            f"{sorted(used_foreign)}"
                            " only populated for the"
                            " other service)"
                        ),
                    })
                    continue

            entry = {
                "control_id": control_id,
                "description": control["description"],
            }
            if result:
                passed.append(entry)
            else:
                entry["severity"] = control.get(
                    "severity", "MEDIUM"
                )
                failed.append(entry)

        total = len(passed) + len(failed)
        percentage = (
            round(len(passed) / total * 100, 1)
            if total > 0
            else 0
        )

        return {
            "framework_name": framework["name"],
            "total_controls": total,
            "passed_controls": len(passed),
            "failed_controls": len(failed),
            "skipped_controls": len(skipped),
            "compliance_percentage": percentage,
            "is_compliant": len(failed) == 0,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        }
