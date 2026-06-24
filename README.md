<p align="center">
  <img src="https://raw.githubusercontent.com/TocConsulting/ecs-eks-security-scanner/main/assets/ecs-eks-security-scanner-logo.png" alt="ECS/EKS Security Scanner" style="max-width: 100%; height: auto;">
</p>

<p align="center">
  <a href="https://pypi.org/project/ecs-eks-security-scanner/"><img src="https://img.shields.io/pypi/v/ecs-eks-security-scanner.svg" alt="PyPI version"></a>
  <a href="https://pepy.tech/project/ecs-eks-security-scanner"><img src="https://static.pepy.tech/badge/ecs-eks-security-scanner" alt="Downloads"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/ecs-eks-security-scanner"><img src="https://img.shields.io/docker/v/tarekcheikh/ecs-eks-security-scanner?label=docker&logo=docker" alt="Docker"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/ecs-eks-security-scanner"><img src="https://img.shields.io/docker/pulls/tarekcheikh/ecs-eks-security-scanner" alt="Docker Pulls"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-brightgreen.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python"></a>
  <a href="https://aws.amazon.com/ecs/"><img src="https://img.shields.io/badge/AWS-ECS-orange.svg" alt="AWS ECS"></a>
  <a href="https://aws.amazon.com/eks/"><img src="https://img.shields.io/badge/AWS-EKS-purple.svg" alt="AWS EKS"></a>
</p>

A comprehensive, production-ready AWS ECS/EKS container security scanner with 45 security checks across 8 categories and compliance mapping for 11 frameworks (128 controls). Supports both ECS and EKS clusters with multi-threaded scanning, secret detection in task definitions, and interactive HTML dashboards.

## Key Features

### **Comprehensive Security Analysis**
- **ECS Cluster Security**: Container Insights, execute command logging, cluster encryption, capacity provider strategy
- **ECS Task Definitions**: Privileged containers, root user, read-only root filesystem, Linux capabilities, network mode, logging, secrets in environment variables, resource limits, PID mode, execution roles
- **ECS Service Security**: ECS Exec access, public IP assignment, circuit breaker, Fargate platform version, security groups
- **EKS Cluster Security**: API endpoint access, secrets encryption, control plane logging, Kubernetes version, managed add-ons, Fargate profiles
- **EKS Node Groups**: Remote access, disk encryption, AMI type, launch templates
- **IAM Security**: Role separation (task vs execution), overly permissive roles, OIDC provider, execution policy on task roles
- **Logging & Monitoring**: GuardDuty runtime monitoring, VPC flow logs
- **Data Protection**: ECR scan-on-push, tag immutability, in-transit encryption

### **Compliance Frameworks**
- **AWS Foundational Security Best Practices (FSBP)**: 16 ECS/EKS controls
- **CIS Amazon EKS Benchmark v2.0.0**: 5 API-assessable controls
- **EKS Node Hardening**: 5 AWS-specific node group controls
- **PCI DSS v4.0.1**: 14 controls
- **HIPAA Security Rule (45 CFR §164)**: 13 controls
- **SOC 2 (2017 TSC, 2022 PoF)**: 15 controls
- **ISO 27001:2022**: 14 controls
- **ISO 27017:2015**: 7 cloud security controls
- **ISO 27018:2019**: 5 PII protection controls (superseded by 2025 edition; migration planned for v1.1)
- **GDPR (EU) 2016/679**: 10 controls
- **NIST SP 800-53 Rev. 5 (Release 5.2.0)**: 24 controls

### **Performance & Usability**
- **Multi-threaded Scanning**: Parallel cluster analysis with ThreadPoolExecutor
- **Rich Console Output**: Progress bars, colored output, and formatted tables
- **Multiple Report Formats**: JSON, CSV, HTML, and compliance-specific reports
- **Beautiful HTML Reports**: Interactive dashboard with Chart.js visualizations
- **Flexible Targeting**: Scan all clusters, specific names/ARNs, or filter by service type (ECS/EKS)

### **Production Ready**
- **Modular Architecture**: Facade pattern with 8 dedicated checker modules
- **Thread-safe Sessions**: Thread-local boto3 session management
- **Graceful Degradation**: AccessDenied errors don't crash scans
- **Dual-service Design**: Unified scanning for both ECS and EKS with shared and service-specific checks
- **Account-level Caching**: ECR results fetched once per account and reused across clusters

## Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/TocConsulting/ecs-eks-security-scanner.git
cd ecs-eks-security-scanner
pip install .
```

### Docker Installation

```bash
# Build from source
docker build -t ecs-eks-security-scanner .
```

### Basic Usage

```bash
# Scan all ECS and EKS clusters
ecs-eks-security-scanner security

# Scan with specific AWS profile
ecs-eks-security-scanner security --profile production

# Scan ECS clusters only
ecs-eks-security-scanner security -s ecs

# Scan EKS clusters only
ecs-eks-security-scanner security -s eks

# Scan specific cluster(s) by name
ecs-eks-security-scanner security -c my-cluster -c my-other-cluster

# Exclude specific clusters
ecs-eks-security-scanner security --exclude-cluster dev --exclude-cluster staging

# Compliance report only
ecs-eks-security-scanner security --compliance-only
```

## Commands

### Security Command

Scan ECS/EKS clusters for security vulnerabilities and compliance issues.

```bash
ecs-eks-security-scanner security [OPTIONS]

Options:
  -s, --service TEXT               Service to scan: ecs, eks, all (default: all)
  -c, --cluster TEXT               Specific cluster name(s)/ARN(s) to scan (multiple)
  --exclude-cluster TEXT           Cluster name(s)/ARN(s) to exclude (multiple)
  --compliance-only                Generate compliance report only
  -r, --region TEXT                AWS region (default: us-east-1)
  -p, --profile TEXT               AWS profile name
  -o, --output-dir TEXT            Output directory (default: ./output)
  -f, --output-format TEXT         Report format: json, csv, html, all (default: all)
  -w, --max-workers INTEGER        Worker threads (default: 5)
  -q, --quiet                      Suppress console output except errors
  -d, --debug                      Enable debug logging
  -h, --help                       Show help

# Top-level options (before the 'security' command):
#   ecs-eks-security-scanner --version
#   ecs-eks-security-scanner --help
```

**Examples:**
```bash
# Scan all clusters with default settings
ecs-eks-security-scanner security

# EKS only, specific region, with HTML output
ecs-eks-security-scanner security -s eks -r eu-west-1 -f html

# High-performance scan with more threads
ecs-eks-security-scanner security -w 20 -p production

# JSON report only, quiet mode (for CI/CD)
ecs-eks-security-scanner security -f json -q

# Fast compliance-only scan
ecs-eks-security-scanner security --compliance-only -f html
```

## Docker Usage

### Basic Docker Commands

```bash
# Show help
docker run --rm ecs-eks-security-scanner --help

# Show security command help
docker run --rm ecs-eks-security-scanner security --help
```

### Security Scanning with Docker

```bash
# Scan using mounted AWS credentials
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  ecs-eks-security-scanner security

# Scan with specific AWS profile
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  ecs-eks-security-scanner security --profile production

# Scan ECS clusters only
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  ecs-eks-security-scanner security -s ecs
```

### Using Environment Variables for AWS Credentials

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  ecs-eks-security-scanner security

# With session token (for temporary credentials/assumed roles)
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  ecs-eks-security-scanner security
```

### Docker Volume Mounts

| Mount | Purpose |
|-------|---------|
| `-v ~/.aws:/root/.aws:ro` | Mount AWS credentials (read-only) |
| `-v $(pwd)/output:/app/output` | Save reports to local directory |

## Prerequisites

### Python Requirements
- Python 3.10 or higher
- Required packages (installed automatically):
  - `boto3>=1.26.0`
  - `botocore>=1.29.0`
  - `rich>=13.0.0`
  - `click>=8.1.0`
  - `jinja2>=3.1.0`

### AWS Requirements
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- Required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:ListClusters",
                "ecs:DescribeClusters",
                "ecs:ListServices",
                "ecs:DescribeServices",
                "ecs:DescribeTaskDefinition",
                "eks:ListClusters",
                "eks:DescribeCluster",
                "eks:ListNodegroups",
                "eks:DescribeNodegroup",
                "eks:ListAddons",
                "eks:ListFargateProfiles",
                "eks:DescribeFargateProfile",
                "ecr:DescribeRepositories",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:ListOpenIDConnectProviders",
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                "ec2:DescribeFlowLogs",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Security Checks

### 45 Checks Across 8 Categories

| # | Category | Checks | Focus |
|---|----------|--------|-------|
| A | ECS Cluster Configuration | 5 | Container Insights, execute command logging, cluster encryption, capacity providers, Service Connect |
| B | ECS Task Definition Security | 10 | Privileged containers, root user, read-only root FS, Linux capabilities, network mode, logging, secrets, resource limits, PID mode, execution role |
| C | ECS Service Security | 5 | ECS Exec, public IP assignment, circuit breaker, Fargate platform version, security groups |
| D | EKS Cluster Configuration | 8 | API endpoint access, secrets encryption, control plane logging, K8s version, security groups, managed add-ons, Fargate profiles |
| E | EKS Node Group Security | 4 | Remote access, disk encryption, AMI type, launch templates |
| F | IAM Security | 5 | Role separation, overly permissive roles, OIDC provider, execution policy on task role, cluster role permissions |
| G | Logging & Monitoring | 4 | Container Insights (alias A.1), control plane logging (alias D.4), GuardDuty, VPC flow logs |
| H | Data Protection | 4 | Cluster encryption (alias A.3/D.3), ECR scan-on-push, ECR tag immutability, in-transit encryption |

### Secret Detection in Task Definitions (B.7)

The scanner decodes and scans ECS task definition environment variables for exposed secrets:

| Pattern | Examples |
|---------|----------|
| AWS Access Keys | `AKIA...`, `ASIA...` |
| AWS Secret Keys | `aws_secret_access_key=...` |
| Passwords | `PASSWORD=`, `DB_PASSWORD=`, `MYSQL_ROOT_PASSWORD=` |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| GitHub Tokens | `ghp_...`, `gho_...`, `ghs_...` |
| API Keys | `api_key=`, `api_token=`, `AUTH_TOKEN=` |
| Connection Strings | `postgres://user:pass@host/db` |

## Modular Architecture

```
ecs_eks_security_scanner/
├── scanner.py                  # Main scanner orchestration (facade pattern)
├── cli.py                      # Click CLI interface
├── compliance.py               # 128 controls across 11 frameworks
├── html_reporter.py            # Jinja2 HTML report generation
├── utils.py                    # Logging, scoring, formatting
├── checks/                     # Security check modules
│   ├── base.py                 # BaseChecker (session factory, error handling)
│   ├── ecs_cluster.py          # A.1-A.5: Container Insights, encryption
│   ├── ecs_task.py             # B.1-B.10: Privileged, secrets, capabilities
│   ├── ecs_service.py          # C.1-C.5: ECS Exec, public IPs, circuit breaker
│   ├── eks_cluster.py          # D.1-D.8: Endpoint access, logging, add-ons
│   ├── eks_nodegroup.py        # E.1-E.4: Remote access, disk encryption
│   ├── iam_security.py         # F.1-F.5: Role separation, OIDC, permissions
│   ├── logging_monitoring.py   # G.3-G.4: GuardDuty, VPC flow logs
│   └── data_protection.py      # H.2-H.4: ECR scanning, tag immutability
└── templates/
    └── report.html             # Interactive HTML dashboard
```

## Security Scoring

Each cluster receives a security score (0-100) starting at **100 points**.

### ECS Scoring

| Security Issue | Points Deducted | Severity |
|----------------|-----------------|----------|
| Privileged containers (B.1) | -20 | CRITICAL |
| Secrets in environment variables (B.7) | -20 | CRITICAL |
| Overly permissive IAM roles (F.2) | -20 | CRITICAL |
| Root user containers (B.2) | -15 | HIGH |
| Non-awsvpc network mode (B.5) | -15 | HIGH |
| Public IP assignment (C.2) | -15 | HIGH |
| Execute command logging disabled (A.2) | -10 | HIGH |
| Read-only root FS not enforced (B.3) | -10 | HIGH |
| Dangerous Linux capabilities (B.4) | -10 | HIGH |
| Container logging not configured (B.6) | -10 | HIGH |
| Host PID mode (B.9) | -10 | HIGH |
| Execution role missing (B.10) | -10 | HIGH |
| Security groups not configured (C.5) | -10 | HIGH |
| Role separation missing (F.1) | -10 | HIGH |
| GuardDuty disabled (G.3) | -10 | HIGH |
| ECR scan-on-push disabled (H.2) | -10 | HIGH |
| Container Insights disabled (A.1) | -5 | MEDIUM |
| Cluster encryption disabled (A.3) | -5 | MEDIUM |
| Resource limits missing (B.8) | -5 | MEDIUM |
| ECS Exec without logging (C.1) | -5 | MEDIUM |
| Circuit breaker disabled (C.3) | -5 | MEDIUM |
| Fargate platform version outdated (C.4) | -5 | MEDIUM |
| Execution policy on task role (F.4) | -5 | MEDIUM |
| VPC flow logs disabled (G.4) | -5 | MEDIUM |
| ECR tag immutability disabled (H.3) | -5 | MEDIUM |
| In-transit encryption missing (H.4) | -5 | MEDIUM |
| Capacity provider strategy missing (A.4) | -2 | LOW |
| Service Connect not configured (A.5) | -2 | LOW |

### EKS Scoring

| Security Issue | Points Deducted | Severity |
|----------------|-----------------|----------|
| Unrestricted public endpoint (D.1) | -20 | CRITICAL |
| End-of-life Kubernetes version (D.5) | -20 | CRITICAL |
| Overly permissive IAM roles (F.2) | -20 | CRITICAL |
| Secrets encryption disabled (D.3) | -15 | HIGH |
| Remote access unrestricted (E.1) | -15 | HIGH |
| OIDC provider not configured (F.3) | -15 | HIGH |
| Private endpoint disabled (D.2) | -10 | HIGH |
| Control plane logging incomplete (D.4) | -10 | HIGH |
| Disk encryption disabled (E.2) | -10 | HIGH |
| GuardDuty disabled (G.3) | -10 | HIGH |
| ECR scan-on-push disabled (H.2) | -10 | HIGH |
| Cluster security group missing (D.6) | -5 | MEDIUM |
| Managed add-ons missing (D.7) | -5 | MEDIUM |
| Fargate profiles private subnets (D.8) | -5 | MEDIUM |
| Insecure AMI type (E.3) | -5 | MEDIUM |
| Overly permissive cluster role (F.5) | -5 | MEDIUM |
| VPC flow logs disabled (G.4) | -5 | MEDIUM |
| ECR tag immutability disabled (H.3) | -5 | MEDIUM |
| In-transit encryption missing (H.4) | -5 | MEDIUM |
| Launch template not used (E.4) | -2 | LOW |

**Formula**: `Score = max(0, 100 - total_deductions)`

### Score Interpretation

| Score Range | Level | Action |
|-------------|-------|--------|
| 90-100 | Excellent | Maintain current posture |
| 70-89 | Good | Address minor gaps |
| 50-69 | Needs Improvement | Fix medium-priority issues |
| 0-49 | Critical | Immediate action required |

## Output Files

The scanner generates reports in the specified output directory:

### JSON Report (`container_scan_region_timestamp.json`)
```json
{
  "summary": {
    "scan_time": "2026-03-11T10:30:45",
    "region": "us-east-1",
    "account_id": "123456789012",
    "total_clusters": 5,
    "ecs_clusters": 3,
    "eks_clusters": 2,
    "average_security_score": 78.5
  },
  "results": [...]
}
```

### CSV Report (`container_scan_region_timestamp.csv`)
Spreadsheet-friendly format with all key metrics and compliance status.

### HTML Report (`container_scan_region_timestamp.html`)
Interactive dashboard with:
- **Executive Summary**: Key metrics and risk indicators
- **Score Distribution**: Bar chart of cluster security scores
- **Compliance Overview**: Table across all 11 frameworks
- **Severity Breakdown**: Doughnut chart of findings by severity
- **Cluster Details**: Table with scores, issue counts, and cluster type badges
- **Per-Cluster Issues**: Detailed finding tables with severity and recommendations

### Compliance Report (`container_compliance_region_timestamp.json`)
Per-cluster compliance evaluation across all 11 frameworks with passed/failed control details.

## Development

### Setting Up Development Environment

```bash
git clone https://github.com/TocConsulting/ecs-eks-security-scanner.git
cd ecs-eks-security-scanner

python -m venv venv
source venv/bin/activate

pip install -e ".[dev]"
```

## Testing

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_compliance.py -v

# Run with coverage
python -m pytest tests/ --cov=ecs_eks_security_scanner --cov-report=html
```

### Test Structure

```
tests/
├── test_cli.py                 # CLI option and command tests
├── test_compliance.py          # 128 controls, 11 frameworks validation
├── test_scoring.py             # ECS and EKS scoring logic
├── test_ecs_cluster.py         # A.1-A.5 checks
├── test_ecs_task.py            # B.1-B.10 checks (privileged, secrets)
├── test_ecs_service.py         # C.1-C.5 checks
├── test_eks_cluster.py         # D.1-D.8 checks (endpoint, logging)
├── test_eks_nodegroup.py       # E.1-E.4 checks
├── test_iam_security.py        # F.1-F.5 checks (roles, permissions)
├── test_logging_monitoring.py  # G.3-G.4 checks (GuardDuty, flow logs)
├── test_data_protection.py     # H.2-H.4 checks (ECR, encryption)
└── test_utils.py               # Logging, formatting utilities
```

Tests use `unittest.mock` for AWS service mocking, allowing comprehensive testing without AWS resources.

## Support & Contributing

### Getting Help
- **Documentation**: Check this README and inline help (`--help`)
- **Issues**: Report bugs via [GitHub Issues](https://github.com/TocConsulting/ecs-eks-security-scanner/issues)

### Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **AWS Security Best Practices**: Based on official AWS security recommendations
- **CIS Benchmarks**: Implements CIS Amazon EKS Benchmark v2.0.0 controls
- **[s3-security-scanner](https://github.com/TocConsulting/s3-security-scanner)**: Architecture and design patterns
- **[ec2-security-scanner](https://github.com/TocConsulting/ec2-security-scanner)**: Architecture and design patterns

---

**Security Notice**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before scanning AWS resources. The tool requires read-only permissions and does not modify any AWS resources.

**Performance Note**: The scanner uses account-level caching for ECR results and thread-safe boto3 sessions for parallel cluster scanning. Use `-w` to adjust parallelism based on your API rate limits.
