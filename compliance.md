# ECS/EKS Security Scanner - Compliance Mapping

## Supported Compliance Frameworks

The tool ships **11 frameworks** with a total of **128 controls**.

> **Disclaimer:** mapping ECS/EKS API-layer checks to broad governance
> frameworks (HIPAA, GDPR, SOC 2, ISO) is **partial technical evidence**, not a
> compliance attestation. CIS Kubernetes Benchmark Section 1 is N/A on managed
> EKS; Sections 4-5 (kubelet, RBAC, Pod Security, NetworkPolicy) need in-cluster
> access and are out of scope for an AWS-API-only scanner. Control IDs are
> verified against authoritative standards - see the [`research/`](research/)
> folder for per-framework sources.

| Framework | Version | Controls | Official Documentation |
|-----------|---------|----------|------------------------|
| AWS FSBP | Latest (ECS.1 retired 2026-03-04) | 16 | https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html |
| CIS Amazon EKS Benchmark | v2.0.0 (API-assessable subset) | 5 | https://www.cisecurity.org/benchmark/kubernetes |
| EKS Node Hardening | - | 5 | AWS-specific node group controls (this tool) |
| PCI DSS | v4.0.1 | 14 | https://www.pcisecuritystandards.org/document_library/ |
| HIPAA Security Rule (45 CFR Part 164) | 2013 Omnibus | 13 | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164 |
| SOC 2 (Trust Services Criteria) | 2017 TSC, Revised Points of Focus 2022 | 15 | https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 |
| ISO/IEC 27001 | 2022 | 14 | https://www.iso.org/standard/27001 |
| ISO/IEC 27017 | 2015 | 7 | https://www.iso.org/standard/43757.html |
| ISO/IEC 27018 | 2019 (superseded by 2025) | 5 | https://www.iso.org/standard/27018 |
| GDPR | (EU) 2016/679 | 10 | https://gdpr-info.eu/ |
| NIST SP 800-53 | Rev. 5 (Release 5.2.0) | 24 | https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search |

---

## AWS Foundational Security Best Practices (AWS-FSBP)

> **Official Documentation:**
> https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html
>
> **Change log:** https://docs.aws.amazon.com/securityhub/latest/userguide/controls-change-log.html

**Coverage: 16 controls (11 ECS + 5 EKS)**. Severities mirror the AWS Security Hub official severity for each control.

**Important Note:** AWS FSBP also defines tagging controls
(ECS.13, ECS.14, ECS.15, EKS.6, EKS.7) which require
organizational tagging policies. These are out of scope for
this scanner as tagging requirements vary by organization.

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| ECS.2 | ECS services should not have public IPs auto-assigned | C.2 | HIGH |
| ECS.3 | Task definitions should not share host process namespace | B.9 | HIGH |
| ECS.4 | ECS containers should run as non-privileged | B.1 | HIGH |
| ECS.5 | ECS containers should use read-only root filesystems | B.3 | HIGH |
| ECS.8 | Secrets should not be in container environment variables | B.7 | HIGH |
| ECS.9 | Task definitions should have a logging configuration | B.6 | HIGH |
| ECS.10 | ECS Fargate services should run on latest platform version | C.4 | MEDIUM |
| ECS.12 | ECS clusters should use Container Insights | A.1 | MEDIUM |
| ECS.16 | ECS task sets should not auto-assign public IPs | C.2 | HIGH |
| ECS.17 | Task definitions should not use host network mode | B.5 | MEDIUM |
| ECS.20 | Task definitions should configure non-root users (Linux) | B.2 | MEDIUM |
| EKS.1 | EKS cluster endpoints should not be publicly accessible | D.1 | HIGH |
| EKS.2 | EKS clusters should run on a supported Kubernetes version | D.5 | HIGH |
| EKS.3 | EKS clusters should use encrypted Kubernetes secrets | D.3 | MEDIUM |
| EKS.8 | EKS clusters should have audit logging enabled | D.4 | MEDIUM |
| EKS.9 | EKS node groups should run on a supported Kubernetes version | D.5 (proxy) | HIGH |

### Out of Scope / Retired FSBP Controls

| Control ID | Description | Reason |
|------------|-------------|--------|
| ECS.1 | Networking modes and user definitions | **Retired by AWS Security Hub on 2026-03-04.** Replacement coverage: ECS.4 + ECS.17 + ECS.20 (+ ECS.21 for Windows). |
| ECS.13 | ECS services should be tagged | Tagging policy varies |
| ECS.14 | ECS clusters should be tagged | Tagging policy varies |
| ECS.15 | ECS task definitions should be tagged | Tagging policy varies |
| ECS.18 | EFS volume in-transit encryption | Requires EFS config analysis |
| ECS.19 | Managed termination protection | Capacity provider specific |
| ECS.21 | Non-admin Windows containers | Windows-specific |
| EKS.6 | EKS clusters should be tagged | Tagging policy varies |
| EKS.7 | EKS identity provider configs tagged | Tagging policy varies |

---

## CIS Amazon EKS Benchmark (CIS-v2.0.0)

> **Official Documentation:**
> https://www.cisecurity.org/benchmark/kubernetes

**Coverage: 5 API-assessable controls (out of ~30+ in CIS v2.0.0).**

**Why only 5?** Most CIS Amazon EKS Benchmark recommendations
(sections 3.1-4.2: kubeconfig file permissions, kubelet flags,
cluster-admin RBAC, privileged container admission) require
**in-cluster inspection** (kubelet binaries, RBAC bindings,
admission controllers). They cannot be evaluated from the AWS
control-plane APIs alone. This tool implements only the CIS
sections that map cleanly to AWS API signals; for the rest,
use `kube-bench` against the cluster.

**Applicability:** EKS clusters only. All controls are marked
not applicable for ECS clusters.

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| 2.1.1 | Enable audit logging | D.4 | HIGH |
| 5.1.1 | Ensure image scanning enabled | H.2 | HIGH |
| 5.3.1 | Encrypt K8s secrets with KMS | D.3 | HIGH |
| 5.4.1 | Restrict public access to API | D.1 | CRITICAL |
| 5.4.2 | Ensure private endpoint enabled | D.2 | HIGH |

### Implementation Details

The previous tool versions misnumbered AWS-specific node-group
checks (SSH access, AMI type, disk encryption, OIDC provider,
node IAM role) as CIS sections 3.1.1, 3.2.1, 3.2.2, 4.1.1,
4.2.1 - those CIS section numbers refer to entirely different
kubelet/RBAC controls. Those AWS-specific checks have been
moved to the **EKS-Hardening** framework below to remove the
false CIS conformance claim.

---

## EKS Node Hardening (EKS-Hardening)

> **Source:** AWS-specific node-group security controls implemented by this scanner.

**Coverage: 5 controls.** These cover EKS node-group security
posture from the AWS-platform perspective (SSH access, AMI
choice, disk encryption, IRSA, cluster IAM role). They are
NOT part of any published CIS benchmark - CIS Kubernetes
recommendations target the Kubernetes layer (kubeconfig,
kubelet, RBAC, admission controllers), not the AWS managed
node groups.

**Applicability:** EKS clusters only.

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| NODE.SSH | Restrict SSH access to EKS node groups | E.1 | HIGH |
| NODE.AMI | Use AWS-supported AMI types (AL2023 / Bottlerocket) | E.3 | MEDIUM |
| NODE.DISK | EKS node group EBS volumes should be encrypted | E.2 | HIGH |
| IAM.IRSA | Configure an IAM OIDC identity provider on the cluster | F.3 | HIGH |
| IAM.ROLE | EKS cluster IAM role should not have admin/wildcard policies | F.5 | MEDIUM |

---

## PCI DSS v4.0

> **Official Documentation:**
> https://www.pcisecuritystandards.org/document_library/

**Coverage: 14 controls**

**Important Note:** These controls map PCI DSS requirements to
container security checks. Achieving full PCI DSS compliance
requires additional controls beyond what an automated scanner
can evaluate.

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| 1.2.1 | Restrict inbound/outbound traffic | C.5, D.6, E.1 | HIGH |
| 1.3.1 | Inbound traffic restricted to CDE | D.1, C.2 | CRITICAL |
| 1.3.2 | Outbound traffic restricted from CDE | G.4 | MEDIUM |
| 2.2.1 | Secure container configurations | B.1, B.3, B.4, B.5, B.9 | CRITICAL |
| 2.2.7 | Non-console admin access encrypted | D.2, H.4 | HIGH |
| 3.4.1 | PAN rendered unreadable (encryption at rest) | D.3, A.3 | HIGH |
| 6.3.3 | Patch vulnerabilities promptly | D.5 | CRITICAL |
| 7.2.1 | Appropriate access (least privilege) | F.2, F.3 | CRITICAL |
| 8.3.1 | Unique identification for users | G.3 | HIGH |
| 8.6.1 | System/service account management | F.1, F.4 | HIGH |
| 10.2.1 | Audit logs enabled for all components | D.4, B.6, A.2 | HIGH |
| 10.3.1 | Protect audit logs from modification | A.2 | HIGH |
| 11.3.1 | Vulnerability scanning performed | H.2 | HIGH |
| 11.5.1 | Intrusion detection (GuardDuty) | G.3 | HIGH |

---

## HIPAA

> **Official Documentation:**
> https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/

**Coverage: 13 controls**

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| 164.312(a)(1) | Access control | F.2, F.3 | HIGH |
| 164.312(a)(2)(i) | Unique user identification | F.1 | HIGH |
| 164.312(a)(2)(iv) | Encryption and decryption | D.3, A.3 | HIGH |
| 164.312(b) | Audit controls | D.4, B.6, A.2, G.4 | HIGH |
| 164.312(c)(1) | Integrity controls | B.3, H.3 | HIGH |
| 164.312(c)(2) | Transmission integrity | H.4 | HIGH |
| 164.312(d) | Person or entity authentication | F.3 | HIGH |
| 164.312(e)(1) | Transmission security | D.2, H.4 | HIGH |
| 164.312(e)(2)(ii) | Encryption in transit | H.4 | HIGH |
| 164.308(a)(1)(ii)(D) | Information system activity review | G.3, G.4 | HIGH |
| 164.308(a)(3) | Workforce security (least privilege) | F.2, F.4 | HIGH |
| 164.308(a)(5)(ii)(B) | Protection from malicious software | H.2, G.3 | HIGH |

---

## SOC 2

> **Official Documentation:**
> https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome

**Coverage: 15 controls**

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| CC6.1 | Logical access security | F.2, F.3, D.1 | HIGH |
| CC6.2 | Access credentials management | F.1, B.7, B.10 | HIGH |
| CC6.3 | Access authorization (least privilege) | F.2, F.4, F.5 | HIGH |
| CC6.6 | Security measures against threats | G.3, H.2 | HIGH |
| CC6.7 | Restrict transmission of data | D.2, H.4 | HIGH |
| CC6.8 | Prevent unauthorized software | B.1, B.3 | CRITICAL |
| CC7.1 | Detection of security events | G.3, D.4, G.4 | HIGH |
| CC7.2 | Monitoring of security events | A.1, G.4 | MEDIUM |
| CC7.3 | Evaluation of security events | A.2, B.6 | HIGH |
| CC8.1 | Change management | C.3, D.7 | MEDIUM |
| A1.2 | System availability (capacity) | B.8, A.4 | MEDIUM |
| C1.1 | Confidentiality (encryption) | D.3, A.3, B.7 | HIGH |
| C1.2 | Confidentiality disposal | H.3 | MEDIUM |
| P6.1 | Privacy (data protection) | B.7, C.1 | HIGH |
| P6.5 | Privacy (access limitation) | F.2, C.2 | HIGH |

---

## ISO 27001:2022

> **Official Documentation:**
> https://www.iso.org/standard/27001

**Coverage: 14 controls**

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| A.5.15 | Access control | F.2, F.3 | HIGH |
| A.5.18 | Access rights (least privilege) | F.1, F.4 | HIGH |
| A.5.23 | Cloud services security | D.1, D.2, C.2 | HIGH |
| A.8.1 | User endpoint devices (node security) | E.1, E.2, E.4 | HIGH |
| A.8.5 | Secure authentication | F.3, D.8 | HIGH |
| A.8.9 | Configuration management | B.1, B.3, B.5, B.9 | HIGH |
| A.8.10 | Information deletion | H.3 | MEDIUM |
| A.8.12 | Data leakage prevention | B.7, C.2 | HIGH |
| A.8.15 | Logging | D.4, B.6, A.2 | HIGH |
| A.8.16 | Monitoring activities | G.3, A.1, D.6 | HIGH |
| A.8.20 | Network security | C.5, G.4 | HIGH |
| A.8.24 | Use of cryptography | D.3, A.3 | HIGH |
| A.8.25 | Secure development lifecycle | H.2, C.3 | MEDIUM |
| A.8.28 | Secure coding | B.4, B.9 | MEDIUM |

---

## ISO 27017:2015

> **Official Documentation:**
> https://www.iso.org/standard/43757.html

**Coverage: 7 controls**

**Note:** ISO 27017 defines 7 additional CLD (cloud) controls
beyond ISO 27002. These controls address cloud-specific security
responsibilities.

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| CLD.6.3.1 | Shared roles and responsibilities | F.1 | HIGH |
| CLD.9.5.1 | Segregation in cloud computing | B.5, B.9 | HIGH |
| CLD.9.5.2 | Virtual machine hardening | B.1, B.3 | HIGH |
| CLD.12.1.5 | Cloud monitoring | A.1, G.3 | HIGH |
| CLD.12.4.5 | Cloud audit logging | D.4, A.2 | HIGH |
| CLD.13.1.4 | Container network security | C.5, C.2, D.6 | HIGH |
| CLD.8.1.5 | Removal of cloud service assets | H.3 | MEDIUM |

---

## ISO 27018:2019

> **Official Documentation:**
> https://www.iso.org/standard/76559.html

**Coverage: 5 controls**

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| A.2.1 | Purpose limitation (data handling) | B.7, C.1 | HIGH |
| A.7.1 | Data minimization | B.8, B.4 | MEDIUM |
| A.10.1 | Cryptographic controls | D.3, A.3, H.4 | HIGH |
| A.11.1 | Equipment security (node hardening) | E.1, E.2 | HIGH |
| A.12.4 | Logging and monitoring | D.4, B.6 | HIGH |

---

## GDPR (General Data Protection Regulation)

> **Official Documentation:**
> https://gdpr.eu/

**Coverage: 10 controls**

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| Art.5(1)(f) | Integrity and confidentiality | D.3, A.3, H.4 | HIGH |
| Art.25 | Data protection by design | B.7, B.3, B.1 | HIGH |
| Art.30 | Records of processing (audit logs) | D.4, B.6, A.2 | HIGH |
| Art.32(1)(a) | Encryption of personal data | D.3, A.3 | HIGH |
| Art.32(1)(b) | Ongoing confidentiality | F.2, C.2, D.1 | HIGH |
| Art.32(1)(c) | Ability to restore availability | C.3, A.4 | MEDIUM |
| Art.32(1)(d) | Testing and evaluation | H.2, G.3 | HIGH |
| Art.33 | Notification of breach | G.3, D.4 | HIGH |
| Art.35 | Data protection impact assessment | B.7, F.2 | HIGH |
| Art.5(1)(e) | Storage limitation | H.3 | MEDIUM |

---

## NIST 800-53 Rev 5

> **Official Documentation:**
> https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

**Coverage: 24 controls**

| Control ID | Description | Check | Severity |
|------------|-------------|-------|----------|
| AC-2 | Account management | F.1, F.3 | HIGH |
| AC-3 | Access enforcement | F.2, D.1 | CRITICAL |
| AC-4 | Information flow enforcement | C.5, G.4, C.2, D.6 | HIGH |
| AC-6 | Least privilege | F.2, F.4, F.5 | HIGH |
| AC-17 | Remote access | D.1, D.2, E.1 | HIGH |
| AU-2 | Event logging | D.4, B.6, C.1 | HIGH |
| AU-3 | Content of audit records | A.2 | HIGH |
| AU-6 | Audit log review and analysis | G.3 | MEDIUM |
| AU-12 | Audit record generation | D.4, A.2, B.6 | HIGH |
| CA-7 | Continuous monitoring | A.1, G.3 | HIGH |
| CM-2 | Baseline configuration | B.5, B.1, B.3, B.8 | HIGH |
| CM-6 | Configuration settings | B.4, B.9, B.10 | MEDIUM |
| CM-7 | Least functionality | B.1, B.4 | HIGH |
| CP-9 | System backup/recovery | C.3 | MEDIUM |
| IA-2 | Identification and authentication | F.3 | HIGH |
| IA-5 | Authenticator management | B.7 | CRITICAL |
| IR-4 | Incident handling | G.3 | HIGH |
| RA-5 | Vulnerability monitoring/scanning | H.2, D.5 | HIGH |
| SC-7 | Boundary protection | D.1, C.2, C.5, D.6 | HIGH |
| SC-8 | Transmission confidentiality | H.4, D.2 | HIGH |
| SC-13 | Cryptographic protection | D.3, A.3 | HIGH |
| SC-28 | Protection of information at rest | D.3, A.3, E.2 | HIGH |
| SI-2 | Flaw remediation | D.5, D.7 | HIGH |
| SI-4 | System monitoring | G.3, A.1 | HIGH |

---

## Overall Compliance Coverage

| Framework | Controls | Description |
|-----------|----------|-------------|
| AWS-FSBP | 16 | ECS and EKS foundational controls |
| CIS EKS v2.0.0 | 5 | API-assessable subset of CIS Amazon EKS |
| EKS-Hardening | 5 | AWS-specific node group controls |
| PCI DSS v4.0.1 | 14 | Payment card data protection |
| HIPAA | 13 | Healthcare data protection (45 CFR §164) |
| SOC 2 | 15 | Trust services criteria (2017 TSC) |
| ISO 27001:2022 | 14 | Information security management |
| ISO 27017:2015 | 7 | Cloud-specific security |
| ISO 27018:2019 | 5 | PII protection (superseded by 2025) |
| GDPR | 10 | EU data protection regulation |
| NIST 800-53 Rev 5 | 24 | Federal security controls |
| **Total** | **128** | |

### Check Coverage by Compliance Frameworks

Every check ID from CONTAINER-CHECKS.md is referenced by at
least one compliance framework:

| Check | Frameworks Referencing It |
|-------|--------------------------|
| A.1 | FSBP, SOC2, ISO27017, NIST, GDPR |
| A.2 | PCI, HIPAA, SOC2, ISO27001, ISO27017, NIST, GDPR |
| A.3 | PCI, HIPAA, SOC2, ISO27001, ISO27018, NIST, GDPR |
| A.4 | SOC2, GDPR |
| A.5 | *(No direct compliance mapping - operational best practice)* |
| B.1 | FSBP, PCI, SOC2, ISO27001, ISO27017, NIST, GDPR |
| B.2 | FSBP |
| B.3 | FSBP, PCI, HIPAA, SOC2, ISO27001, ISO27017, NIST, GDPR |
| B.4 | PCI, ISO27001, ISO27018, NIST |
| B.5 | FSBP, PCI, ISO27001, ISO27017, NIST |
| B.6 | FSBP, PCI, HIPAA, SOC2, ISO27001, ISO27018, NIST, GDPR |
| B.7 | FSBP, SOC2, ISO27001, ISO27018, NIST, GDPR |
| B.8 | SOC2, ISO27018, NIST |
| B.9 | FSBP, PCI, ISO27001 |
| B.10 | SOC2, NIST |
| C.1 | SOC2, ISO27018, NIST |
| C.2 | FSBP, PCI, ISO27001, ISO27017, NIST, GDPR |
| C.3 | SOC2, ISO27001, NIST, GDPR |
| C.4 | FSBP |
| C.5 | PCI, ISO27001, ISO27017, NIST |
| D.1 | FSBP, CIS, PCI, SOC2, ISO27001, NIST, GDPR |
| D.2 | CIS, PCI, SOC2, ISO27001, NIST |
| D.3 | FSBP, CIS, PCI, HIPAA, SOC2, ISO27001, ISO27018, NIST, GDPR |
| D.4 | FSBP, CIS, PCI, HIPAA, SOC2, ISO27001, ISO27017, ISO27018, NIST, GDPR |
| D.5 | FSBP, PCI, NIST |
| D.6 | ISO27001, ISO27017, NIST |
| D.7 | SOC2, NIST |
| D.8 | ISO27001 |
| E.1 | CIS, PCI, ISO27001, ISO27018, NIST |
| E.2 | CIS, ISO27001, ISO27018, NIST |
| E.3 | CIS |
| E.4 | ISO27001 |
| F.1 | HIPAA, SOC2, ISO27001, ISO27017, NIST |
| F.2 | HIPAA, PCI, SOC2, ISO27001, NIST, GDPR |
| F.3 | CIS, HIPAA, PCI, SOC2, ISO27001, NIST |
| F.4 | PCI, HIPAA, SOC2, ISO27001, NIST |
| F.5 | CIS, SOC2, NIST |
| G.3 | PCI, HIPAA, SOC2, ISO27001, ISO27017, NIST, GDPR |
| G.4 | PCI, HIPAA, SOC2, ISO27001, NIST |
| H.2 | CIS, PCI, HIPAA, SOC2, ISO27001, NIST, GDPR |
| H.3 | HIPAA, SOC2, ISO27001, ISO27017, GDPR |
| H.4 | PCI, HIPAA, SOC2, ISO27001, ISO27018, NIST, GDPR |

**Note:** A.5 has no direct compliance mapping. It remains as
an operational best practice check.

### Compliance Evaluation Method

Each compliance control is implemented as a lambda function that
receives the full cluster scan results dict and returns a boolean.

**Fail-closed defaults for "bad thing" checks:**
```python
"ECS.4": {
    "description": "ECS containers should run as non-privileged",
    "severity": "CRITICAL",
    "check": lambda r: not r.get(
        "privileged_containers", {}
    ).get("has_privileged", True),
}
```
When `has_privileged` is missing, default `True` (assume bad)
then `not True` = `False` (fail).

**Fail-closed defaults for "good thing" checks:**
```python
"EKS.3": {
    "description": "Clusters should use encrypted secrets",
    "severity": "HIGH",
    "check": lambda r: r.get(
        "secrets_encryption", {}
    ).get("enabled", False),
}
```
When `enabled` is missing, default `False` (fail).

### Framework Applicability

Each compliance control carries an `applies_to` metadata field:
- `"ecs"` - Only evaluated for ECS clusters
- `"eks"` - Only evaluated for EKS clusters
- `"both"` - Evaluated for all cluster types

This replaces naive prefix-based filtering and ensures controls
like CIS 2.1.1 (EKS-only) and ECS.4 (ECS-only) are correctly
skipped based on cluster type regardless of control ID format.
