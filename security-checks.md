# ECS/EKS Security Scanner - Security Checks

## Overview

This document defines all security checks performed by the
ECS/EKS Security Scanner. Checks are organized into 8 categories
covering both ECS and EKS services, with shared checks where
the security concern applies to both orchestrators.

**Total: 45 checks across 8 categories**

**Note:** G.1, G.2, and H.1 are compliance-oriented references
to checks B.6, A.1, and B.7 respectively. They share the same
underlying evaluation logic but exist as separate IDs so
compliance frameworks can reference them consistently. They do
not add separate scoring deductions.

---

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|-------------------|
| ECS Best Practices | https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/ |
| EKS Best Practices | https://aws.github.io/aws-eks-best-practices/ |
| ECS Security | https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security.html |
| EKS Security | https://docs.aws.amazon.com/eks/latest/userguide/security.html |
| AWS FSBP ECS Controls | https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html |
| AWS FSBP EKS Controls | https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html |
| CIS EKS Benchmark | https://www.cisecurity.org/benchmark/amazon_elastic_kubernetes_service |
| ECR Image Scanning | https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html |

---

## Security Check Categories

- [A. ECS Cluster Security](#a-ecs-cluster-security) (5 checks)
- [B. ECS Task Definition Security](#b-ecs-task-definition-security) (10 checks)
- [C. ECS Service Security](#c-ecs-service-security) (5 checks)
- [D. EKS Cluster Security](#d-eks-cluster-security) (8 checks)
- [E. EKS Node Group Security](#e-eks-node-group-security) (4 checks)
- [F. IAM & Access Control](#f-iam--access-control) (5 checks)
- [G. Logging & Monitoring](#g-logging--monitoring) (4 checks)
- [H. Data Protection](#h-data-protection) (4 checks)

---

## A. ECS Cluster Security

### A.1 - Container Insights Monitoring Enabled

**Check ID:** A.1
**Severity:** MEDIUM
**AWS FSBP:** ECS.12
**Description:** Verifies that ECS clusters have Container Insights
enabled for monitoring container-level metrics and logs.

**Why This Check Is Critical:**
Container Insights provides detailed performance and diagnostic data
for ECS clusters, including CPU, memory, disk, and network metrics
at the task and service level. Without it, operators lack visibility
into container health, resource contention, and anomalous behavior.

**boto3 API Calls:**
- `ecs.describe_clusters(clusters=[...], include=['SETTINGS'])`
- Check `settings` array for `name=containerInsights, value=enabled`

---

### A.2 - Execute Command Logging Configured

**Check ID:** A.2
**Severity:** HIGH
**Description:** Verifies that ECS clusters have Execute Command
logging properly configured to audit interactive container sessions.

**Why This Check Is Critical:**
ECS Exec allows shell access into running containers. Without
audit logging, an attacker who gains exec access can operate
undetected. Logging must capture commands to CloudWatch Logs
or S3 for forensic analysis.

**boto3 API Calls:**
- `ecs.describe_clusters(clusters=[...], include=['CONFIGURATIONS'])`
- Check `configuration.executeCommandConfiguration` for
  `logging != NONE` and `logConfiguration` presence

---

### A.3 - Cluster Encryption with KMS

**Check ID:** A.3
**Severity:** MEDIUM
**Description:** Verifies that ECS clusters use a customer-managed
KMS key for encryption of managed storage and configuration data.

**Why This Check Is Critical:**
Using a customer-managed KMS key provides full control over the
encryption key lifecycle, enables key rotation policies, and
allows granular access control through KMS key policies. Without
it, data is encrypted with AWS-managed keys that cannot be
audited or rotated by the customer.

**boto3 API Calls:**
- `ecs.describe_clusters(clusters=[...], include=['CONFIGURATIONS'])`
- Check `configuration.managedStorageConfiguration.kmsKeyId`

---

### A.4 - Default Capacity Provider Strategy Set

**Check ID:** A.4
**Severity:** LOW
**Description:** Verifies that ECS clusters have a default capacity
provider strategy configured.

**Why This Check Is Critical:**
A default capacity provider strategy ensures tasks are launched
with consistent infrastructure settings. Without it, tasks may
be launched on unintended infrastructure (e.g., on EC2 when
Fargate was intended), potentially bypassing security controls.

**boto3 API Calls:**
- `ecs.describe_clusters(clusters=[...])`
- Check `defaultCapacityProviderStrategy` is non-empty

---

### A.5 - ECS Cluster Service Connect Default Namespace

**Check ID:** A.5
**Severity:** LOW
**Description:** Verifies that ECS clusters have a Service Connect
default namespace configured for service discovery and mutual TLS.

**Why This Check Is Critical:**
Service Connect provides built-in service mesh capabilities with
mutual TLS encryption between services. Without a configured
namespace, inter-service communication may occur unencrypted
over the network.

**boto3 API Calls:**
- `ecs.describe_clusters(clusters=[...])`
- Check `serviceConnectDefaults.namespace` is present

---

## B. ECS Task Definition Security

### B.1 - No Privileged Containers

**Check ID:** B.1
**Severity:** CRITICAL
**AWS FSBP:** ECS.4
**Description:** Verifies that no container definitions in a task
use `privileged: true`.

**Why This Check Is Critical:**
Privileged containers have root-level access to the host's kernel,
devices, and filesystem. A container escape from a privileged
container gives full host control. This is the most dangerous
container misconfiguration. Fargate does not support privileged
mode, but EC2 launch type does.

**Attack Scenario:**
1. Attacker compromises an application running in a privileged
   container
2. Attacker mounts the host filesystem via /dev
3. Attacker escapes the container and gains full host access
4. Attacker pivots to other containers and the ECS agent

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check each `containerDefinitions[].privileged != true`

---

### B.2 - No Root User Containers

**Check ID:** B.2
**Severity:** HIGH
**AWS FSBP:** ECS.20
**Description:** Verifies that container definitions specify a
non-root user (not UID 0, not "root", and `user` field is set).

**Why This Check Is Critical:**
Running as root inside a container increases the blast radius of
any vulnerability. If combined with a kernel exploit or container
escape, the attacker gains root on the host. Non-root containers
limit damage to application-level access.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check each `containerDefinitions[].user` is set and not
  "root" or "0"

---

### B.3 - Read-Only Root Filesystem

**Check ID:** B.3
**Severity:** HIGH
**AWS FSBP:** ECS.5
**Description:** Verifies that container definitions enable
`readonlyRootFilesystem: true`.

**Why This Check Is Critical:**
A read-only root filesystem prevents malware from writing to the
container's filesystem, blocks persistence mechanisms, and prevents
modification of application binaries. Writable directories should
be explicitly mounted as tmpfs or volumes.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check each `containerDefinitions[].readonlyRootFilesystem == true`

---

### B.4 - Linux Capabilities Restricted

**Check ID:** B.4
**Severity:** HIGH
**Description:** Verifies that container definitions drop dangerous
Linux capabilities (especially SYS_ADMIN, NET_ADMIN, NET_RAW) and
do not add unnecessary capabilities.

**Why This Check Is Critical:**
Docker containers receive a default set of 14 Linux capabilities.
Capabilities like SYS_ADMIN enable mounting filesystems and
namespace manipulation - near-equivalent to full root access.
NET_RAW allows packet crafting for network attacks. Best practice
is to drop ALL and add only what's needed.

**Dangerous capabilities checked:** SYS_ADMIN, NET_ADMIN, NET_RAW,
SYS_PTRACE, SYS_RAWIO, SYS_MODULE, DAC_OVERRIDE, DAC_READ_SEARCH,
FOWNER, CHOWN, KILL, AUDIT_WRITE, SYS_CHROOT, MKNOD,
SETUID, SETGID

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check `containerDefinitions[].linuxParameters.capabilities`
  for `add` list (should not contain dangerous caps) and `drop`
  list (should contain ALL or specific dangerous ones)

---

### B.5 - Network Mode is awsvpc

**Check ID:** B.5
**Severity:** HIGH
**AWS FSBP:** ECS.17
**Description:** Verifies that task definitions use the `awsvpc`
network mode and specifically do not use `host` network mode.
Also flags `bridge` and `none` as non-compliant.

**Why This Check Is Critical:**
The `awsvpc` network mode gives each task its own ENI and security
group, enabling task-level network isolation. The `host` mode
shares the host's network namespace (no isolation). The `bridge`
mode provides limited isolation but shares a single ENI. Only
`awsvpc` supports security group per-task enforcement.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check `networkMode == "awsvpc"`

---

### B.6 - Container Logging Configured

**Check ID:** B.6
**Severity:** HIGH
**AWS FSBP:** ECS.9
**Description:** Verifies that every container definition has a
`logConfiguration` with a logging driver (awslogs, splunk,
awsfirelens, etc.).

**Why This Check Is Critical:**
Without logging, container stdout/stderr output is lost. Security
events, application errors, and audit trails become invisible.
The `awslogs` driver sends logs to CloudWatch Logs for
centralized analysis and alerting.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check each `containerDefinitions[].logConfiguration` is present
  and `logDriver` is set

---

### B.7 - No Secrets in Environment Variables

**Check ID:** B.7
**Severity:** CRITICAL
**AWS FSBP:** ECS.8
**Description:** Verifies that container definitions do not contain
secrets (passwords, API keys, tokens) as plaintext environment
variables. Secrets should use `secrets` with valueFrom referencing
Secrets Manager or SSM Parameter Store.

**Why This Check Is Critical:**
Plaintext environment variables are visible in the ECS console,
task metadata endpoint, CloudWatch Logs (if env vars are logged),
and `docker inspect`. They are stored unencrypted in the task
definition. Using `secrets` with Secrets Manager or SSM ensures
values are injected at runtime and never stored in the definition.

**Detection patterns (environment variable names):**
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, PASSWORD, SECRET,
TOKEN, API_KEY, PRIVATE_KEY, DATABASE_URL, CONNECTION_STRING,
CREDENTIALS, CLIENT_SECRET, OAUTH, JWT_SECRET, GITHUB_TOKEN,
SLACK_TOKEN, STRIPE_KEY, SENDGRID_API_KEY, ENCRYPTION_KEY,
SIGNING_KEY.

**Detection patterns (value formats):**
AWS access key format (AKIA...), base64-encoded strings longer
than 40 characters in keys matching SECRET/KEY/TOKEN patterns.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check `containerDefinitions[].environment[].name` against
  known secret patterns and `value` against credential formats

---

### B.8 - Resource Limits Defined

**Check ID:** B.8
**Severity:** MEDIUM
**Description:** Verifies that task definitions have CPU and memory
limits set at the task or container level.

**Why This Check Is Critical:**
Without resource limits, a single container can consume all
available CPU and memory on the host, starving other containers.
This enables denial-of-service within the cluster and makes
resource accounting impossible.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check `cpu` and `memory` at task level, or `cpu` and `memory`
  on each container definition

---

### B.9 - PID Mode Not Host

**Check ID:** B.9
**Severity:** HIGH
**AWS FSBP:** ECS.3
**Description:** Verifies that task definitions do not set
`pidMode: host`, which shares the host's process namespace.

**Why This Check Is Critical:**
Host PID mode allows containers to see and signal all processes
on the host, including other containers and the ECS agent. An
attacker can inspect environment variables of other processes
(potentially containing secrets), send signals to crash services,
or use ptrace on host processes.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check `pidMode != "host"`

---

### B.10 - Task Execution Role Configured

**Check ID:** B.10
**Severity:** HIGH
**Description:** Verifies that task definitions have an execution
role configured for pulling images and sending logs.

**Why This Check Is Critical:**
The execution role is used by the ECS agent to pull container
images from ECR and send container logs to CloudWatch. Without
it, the ECS agent falls back to the EC2 instance role (if EC2
launch type) which typically has broader permissions. On Fargate,
an execution role is required for any ECR or CloudWatch
integration.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Check `executionRoleArn` is present

---

## C. ECS Service Security

### C.1 - ECS Exec Not Enabled (or Logged)

**Check ID:** C.1
**Severity:** MEDIUM
**Description:** Verifies that services do not have ECS Exec
enabled, or if enabled, that the cluster has Execute Command
logging configured (see A.2).

**Why This Check Is Critical:**
ECS Exec provides interactive shell access to running containers,
equivalent to SSH access. While useful for debugging, it creates
a direct path into containers that bypasses network security
controls. If enabled, it must be paired with audit logging.

**boto3 API Calls:**
- `ecs.describe_services(cluster=..., services=[...])`
- Check `enableExecuteCommand` on each service

---

### C.2 - Public IP Not Auto-Assigned

**Check ID:** C.2
**Severity:** HIGH
**AWS FSBP:** ECS.2, ECS.16
**Description:** Verifies that ECS services and task sets using
awsvpc network mode do not auto-assign public IP addresses.

**Why This Check Is Critical:**
Tasks with public IPs are directly reachable from the internet.
Container workloads should run in private subnets behind a load
balancer or NAT gateway. Direct internet exposure increases the
attack surface dramatically.

**boto3 API Calls:**
- `ecs.describe_services(cluster=..., services=[...])`
- Check `networkConfiguration.awsvpcConfiguration.assignPublicIp
  != "ENABLED"`

---

### C.3 - Deployment Circuit Breaker Enabled

**Check ID:** C.3
**Severity:** MEDIUM
**Description:** Verifies that ECS services have the deployment
circuit breaker enabled with rollback.

**Why This Check Is Critical:**
Without a circuit breaker, a bad deployment (including one with
security vulnerabilities or misconfigurations) will keep trying
to roll out indefinitely. The circuit breaker automatically
rolls back failed deployments, ensuring the known-good
configuration is restored.

**boto3 API Calls:**
- `ecs.describe_services(cluster=..., services=[...])`
- Check `deploymentConfiguration.deploymentCircuitBreaker.enable`
  and `rollback` are true

---

### C.4 - Fargate Platform Version Current

**Check ID:** C.4
**Severity:** MEDIUM
**AWS FSBP:** ECS.10
**Description:** Verifies that Fargate services use the latest
available platform version.

**Why This Check Is Critical:**
Older Fargate platform versions may lack security patches,
ephemeral storage encryption, and other hardening features. The
latest platform version includes all current security fixes and
features like ephemeral storage encryption at rest.

**Implementation Note:** When a service specifies "LATEST", the
`describe_services` API returns the resolved version (e.g.,
"1.4.0"), not the string "LATEST". The check must compare the
resolved `platformVersion` against the known latest version for
the platform family (LINUX: "1.4.0", WINDOWS: "1.0.0"), or
check that the `platformVersion` was originally set to "LATEST"
via the task definition or service configuration.

**boto3 API Calls:**
- `ecs.describe_services(cluster=..., services=[...])`
- Check `platformVersion` against known latest versions
- Only applies to services with `launchType == "FARGATE"`

---

### C.5 - Service Uses Security Groups

**Check ID:** C.5
**Severity:** HIGH
**Description:** Verifies that ECS services using awsvpc network
mode have security groups configured to restrict traffic.

**Why This Check Is Critical:**
Security groups are the primary network firewall for tasks in
awsvpc mode. Without properly configured security groups,
containers may accept traffic from any source or send traffic
to any destination, defeating network segmentation.

**boto3 API Calls:**
- `ecs.describe_services(cluster=..., services=[...])`
- Check `networkConfiguration.awsvpcConfiguration.securityGroups`
  is non-empty
- `ec2.describe_security_groups(GroupIds=[...])` for rule analysis

---

## D. EKS Cluster Security

### D.1 - Cluster Endpoint Not Publicly Accessible

**Check ID:** D.1
**Severity:** CRITICAL
**AWS FSBP:** EKS.1
**CIS EKS:** 5.4.1
**Description:** Verifies that the EKS API server endpoint is not
publicly accessible, or if public, that access is restricted to
specific CIDR blocks.

**Why This Check Is Critical:**
A publicly accessible Kubernetes API server endpoint exposes the
cluster control plane to the internet. Even with authentication,
this increases the attack surface for credential stuffing, API
exploits, and denial-of-service attacks. The endpoint should be
private-only or restricted to known CIDRs.

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Check `resourcesVpcConfig.endpointPublicAccess` and
  `publicAccessCidrs` (should not contain "0.0.0.0/0")

---

### D.2 - Private Endpoint Enabled

**Check ID:** D.2
**Severity:** HIGH
**CIS EKS:** 5.4.2
**Description:** Verifies that the EKS cluster has private endpoint
access enabled so nodes communicate with the control plane via
the VPC.

**Why This Check Is Critical:**
Without private endpoint access, all kubelet and node-to-control
plane communication traverses the public internet, even if the
public endpoint is restricted. Enabling the private endpoint
ensures node traffic stays within the VPC.

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Check `resourcesVpcConfig.endpointPrivateAccess == true`

---

### D.3 - Secrets Encryption with KMS

**Check ID:** D.3
**Severity:** HIGH
**AWS FSBP:** EKS.3
**CIS EKS:** 5.3.1
**Description:** Verifies that EKS cluster Kubernetes secrets are
encrypted at rest using a customer-managed KMS key (envelope
encryption).

**Why This Check Is Critical:**
By default, Kubernetes secrets are stored as base64-encoded
plaintext in etcd. Enabling KMS envelope encryption ensures
secrets are encrypted at rest with a key you control. Without it,
anyone with etcd access or an etcd backup can read all secrets.

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Check `encryptionConfig` contains a provider with
  `keyArn` for resource type `secrets`

---

### D.4 - Control Plane Logging Enabled (All 5 Types)

**Check ID:** D.4
**Severity:** HIGH
**AWS FSBP:** EKS.8
**CIS EKS:** 2.1.1
**Description:** Verifies that all 5 EKS control plane log types
are enabled: api, audit, authenticator, controllerManager,
scheduler.

**Why This Check Is Critical:**
Control plane logs are essential for security monitoring and
incident response. The `audit` log records all API requests
(who did what, when). The `authenticator` log tracks
authentication attempts. Missing log types create blind spots
in security monitoring.

**Required log types:** api, audit, authenticator,
controllerManager, scheduler

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Check `logging.clusterLogging` has all 5 types enabled

---

### D.5 - Kubernetes Version Supported

**Check ID:** D.5
**Severity:** CRITICAL
**AWS FSBP:** EKS.2
**Description:** Verifies that the EKS cluster runs a supported
Kubernetes version (not end-of-life).

**Why This Check Is Critical:**
End-of-life Kubernetes versions no longer receive security patches.
Known CVEs remain unpatched, and AWS eventually removes support
for the version. Running unsupported versions violates every
compliance framework.

**Supported versions:** The scanner maintains a hardcoded list
of currently supported EKS Kubernetes versions (e.g., 1.28-1.32).
This list must be updated when AWS releases new versions or
deprecates old ones.

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Check `version` against hardcoded supported versions list

---

### D.6 - Cluster Security Group Configured

**Check ID:** D.6
**Severity:** MEDIUM
**Description:** Verifies that the EKS cluster has a configured
cluster security group for control plane communication.

**Why This Check Is Critical:**
The cluster security group controls network traffic between the
control plane and worker nodes. A missing or misconfigured
security group can allow unauthorized access to the API server
or block legitimate node communication.

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Check `resourcesVpcConfig.clusterSecurityGroupId` is present

---

### D.7 - Required Add-ons Installed

**Check ID:** D.7
**Severity:** MEDIUM
**Description:** Verifies that critical EKS add-ons (vpc-cni,
kube-proxy, coredns) are installed via managed add-ons (not
self-managed).

**Why This Check Is Critical:**
Managed add-ons are automatically updated by AWS with security
patches. Self-managed add-ons require manual updates and are
frequently left on vulnerable versions. The VPC CNI plugin
controls pod networking and IP allocation - a compromised or
outdated CNI can expose pod traffic.

**Required add-ons:** vpc-cni, kube-proxy, coredns

**boto3 API Calls:**
- `eks.list_addons(clusterName=...)`
- `eks.describe_addon(clusterName=..., addonName=...)`
- Check status is ACTIVE and version is current

---

### D.8 - EKS Fargate Profile Security

**Check ID:** D.8
**Severity:** MEDIUM
**Description:** Verifies that EKS Fargate profiles have
appropriate subnet and selector configurations.

**Why This Check Is Critical:**
Fargate profiles determine which pods run on Fargate and in which
subnets. Misconfigured selectors may cause unexpected pod
scheduling. Fargate pods should run in private subnets for
network isolation.

**boto3 API Calls:**
- `eks.list_fargate_profiles(clusterName=...)`
- `eks.describe_fargate_profile(clusterName=...,
  fargateProfileName=...)`
- Check `subnets` list and `selectors` configuration

---

## E. EKS Node Group Security

### E.1 - Remote Access Restricted

**Check ID:** E.1
**Severity:** HIGH
**CIS EKS:** 3.1.1
**Description:** Verifies that EKS managed node groups do not allow
unrestricted SSH access (port 22 open to 0.0.0.0/0).

**Why This Check Is Critical:**
SSH access to worker nodes allows direct interaction with the
node's operating system, bypassing Kubernetes RBAC controls.
Unrestricted SSH from the internet exposes nodes to brute-force
attacks and credential stuffing. Access should be limited to
bastion hosts or SSM Session Manager.

**boto3 API Calls:**
- `eks.describe_nodegroup(clusterName=..., nodegroupName=...)`
- Check `remoteAccess` configuration
- If `ec2SshKey` is set, check `sourceSecurityGroups` is non-empty

---

### E.2 - Node Group Disk Encryption

**Check ID:** E.2
**Severity:** HIGH
**Description:** Verifies that EKS node group instances use
encrypted EBS volumes.

**Why This Check Is Critical:**
Worker node disks contain container images, container filesystem
layers, emptyDir volumes, and potentially cached secrets.
Unencrypted disks expose this data if the underlying EBS volume
is snapshotted or the instance is compromised.

**boto3 API Calls:**
- `eks.describe_nodegroup(clusterName=..., nodegroupName=...)`
- Check `diskSize` presence and `launchTemplate` for encryption
- If using launch template, inspect template's block device
  mappings for encryption

---

### E.3 - Secure AMI Type

**Check ID:** E.3
**Severity:** MEDIUM
**Description:** Verifies that EKS node groups use a recommended
AMI type (AL2023, Bottlerocket, or custom hardened AMI).

**Why This Check Is Critical:**
Bottlerocket and AL2023 are purpose-built for containers with
minimal attack surface, immutable root filesystem, and automatic
security updates. Generic AMIs include unnecessary packages
and services that increase the attack surface.

**boto3 API Calls:**
- `eks.describe_nodegroup(clusterName=..., nodegroupName=...)`
- Check `amiType` against recommended types:
  AL2023_x86_64_STANDARD, AL2023_ARM_64_STANDARD,
  BOTTLEROCKET_x86_64, BOTTLEROCKET_ARM_64

---

### E.4 - Node Group Uses Launch Template

**Check ID:** E.4
**Severity:** LOW
**Description:** Verifies that EKS node groups use a launch
template for consistent, auditable node configuration.

**Why This Check Is Critical:**
Launch templates provide version-controlled, repeatable node
configurations. Without them, node configuration depends on
node group defaults which may not include desired hardening
(encrypted volumes, IMDSv2, security groups).

**boto3 API Calls:**
- `eks.describe_nodegroup(clusterName=..., nodegroupName=...)`
- Check `launchTemplate` is present

---

## F. IAM & Access Control

### F.1 - Task/Execution Role Separation

**Check ID:** F.1
**Severity:** HIGH
**Description:** Verifies that ECS task definitions use separate
IAM roles for the task role (`taskRoleArn`) and execution role
(`executionRoleArn`), and that they are not the same ARN.

**Why This Check Is Critical:**
The execution role is used by the ECS agent for infrastructure
operations (pull images, push logs). The task role is used by the
application code for business logic (access DynamoDB, S3, etc.).
Using the same role for both means the application code has
permissions to pull images and manage logs - violating least
privilege.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- Compare `taskRoleArn` and `executionRoleArn`

---

### F.2 - Roles Not Overly Permissive

**Check ID:** F.2
**Severity:** CRITICAL
**Description:** Verifies that ECS task roles and EKS node roles
do not have admin-level permissions (Action: *, Resource: *) or
known admin managed policies attached.

**Why This Check Is Critical:**
An overly permissive role on a container means any code running
in that container - including compromised dependencies or injected
code - has full AWS account access. Container roles should follow
strict least-privilege with only the specific permissions the
application needs.

**Admin policy ARNs checked:**
- arn:aws:iam::aws:policy/AdministratorAccess
- arn:aws:iam::aws:policy/PowerUserAccess
- arn:aws:iam::aws:policy/IAMFullAccess

**boto3 API Calls:**
- `iam.list_attached_role_policies(RoleName=...)`
- `iam.list_role_policies(RoleName=...)` (inline policies)
- `iam.get_role_policy(RoleName=..., PolicyName=...)` for
  inline policy documents
- Check for `Action: "*"` with `Resource: "*"`

---

### F.3 - EKS OIDC Provider Configured (IRSA)

**Check ID:** F.3
**Severity:** HIGH
**Description:** Verifies that EKS clusters have an OIDC provider
associated for IAM Roles for Service Accounts (IRSA).

**Why This Check Is Critical:**
Without IRSA, all pods on a node share the node's IAM role, making
least-privilege impossible. IRSA allows individual Kubernetes
service accounts to assume specific IAM roles, enabling true
per-pod permission boundaries. This is the EKS equivalent of
ECS task roles.

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Check `identity.oidc.issuer` is present
- `iam.list_open_id_connect_providers()` to verify the OIDC
  provider is registered in IAM

---

### F.4 - Execution Role Not Used as Task Role

**Check ID:** F.4
**Severity:** MEDIUM
**Description:** Verifies that ECS task definitions do not use
the AmazonECSTaskExecutionRolePolicy on their task role.

**Why This Check Is Critical:**
The AmazonECSTaskExecutionRolePolicy grants permissions to pull
ECR images and write CloudWatch logs - infrastructure operations
that application code should never need. Attaching this policy
to the task role gives the application unnecessary access to ECR
and CloudWatch APIs.

**boto3 API Calls:**
- `ecs.describe_task_definition(taskDefinition=...)`
- `iam.list_attached_role_policies(RoleName=...)`
- Check task role does not have
  AmazonECSTaskExecutionRolePolicy attached

---

### F.5 - EKS Cluster Role Least Privilege

**Check ID:** F.5
**Severity:** MEDIUM
**Description:** Verifies that the EKS cluster IAM role uses
the standard AmazonEKSClusterPolicy and does not have excessive
additional permissions.

**Why This Check Is Critical:**
The EKS cluster role is used by the Kubernetes control plane.
Excessive permissions on this role could be exploited through
Kubernetes API server vulnerabilities to escalate privileges
in the AWS account.

**boto3 API Calls:**
- `eks.describe_cluster(name=...)`
- Extract role name from `roleArn`
- `iam.list_attached_role_policies(RoleName=...)`
- Check for admin/wildcard policies

---

## G. Logging & Monitoring

### G.1 - Container-Level Logging Enabled

**Check ID:** G.1
**Severity:** HIGH
**Description:** Verifies that container workloads send logs to
a centralized logging service (CloudWatch Logs via awslogs driver
for ECS, or CloudWatch/Fluent Bit for EKS).

**Why This Check Is Critical:**
Without centralized logging, security events from containers are
lost when the container stops. Logs are essential for incident
response, compliance auditing, and anomaly detection. This check
covers ECS task definition log configuration.

**boto3 API Calls:**
- (Same as B.6 - evaluated per task definition)

---

### G.2 - Container Insights Enabled

**Check ID:** G.2
**Severity:** MEDIUM
**Description:** Verifies that Container Insights is enabled on
ECS clusters and EKS clusters for performance and security
monitoring.

**Why This Check Is Critical:**
Container Insights provides automated dashboards and anomaly
detection for container metrics. It enables detection of resource
abuse, cryptomining, and denial-of-service at the container level.

**boto3 API Calls:**
- ECS: (Same as A.1)
- EKS: `eks.describe_cluster(name=...)` - check for
  `logging` configuration

---

### G.3 - GuardDuty EKS/ECS Protection Enabled

**Check ID:** G.3
**Severity:** HIGH
**Description:** Verifies that Amazon GuardDuty has EKS Audit Log
Monitoring and EKS Runtime Monitoring (or ECS Runtime Monitoring)
enabled for threat detection.

**Why This Check Is Critical:**
GuardDuty analyzes EKS audit logs for suspicious Kubernetes API
activity (privilege escalation, anonymous access, known attack
tools). Runtime Monitoring detects threats at the OS level inside
containers (reverse shells, cryptocurrency mining, malware).

**boto3 API Calls:**
- `guardduty.list_detectors()`
- `guardduty.get_detector(DetectorId=...)`
- Check feature statuses for EKS_AUDIT_LOGS, EKS_RUNTIME_MONITORING,
  ECS_RUNTIME_MONITORING (under RUNTIME_MONITORING)

---

### G.4 - VPC Flow Logs for Container VPCs

**Check ID:** G.4
**Severity:** MEDIUM
**Description:** Verifies that VPCs used by ECS/EKS clusters have
VPC Flow Logs enabled for network traffic analysis.

**Why This Check Is Critical:**
VPC Flow Logs capture network traffic metadata for containers
running in awsvpc mode and EKS pods. Without flow logs, network
reconnaissance, data exfiltration, and lateral movement by
compromised containers cannot be detected through network analysis.

**boto3 API Calls:**
- `ec2.describe_flow_logs(Filters=[{'Name': 'resource-id',
  'Values': [vpc_id]}])`
- VPC IDs extracted from ECS service network config and
  EKS cluster VPC config

---

## H. Data Protection

### H.1 - Secrets Use Secrets Manager or SSM

**Check ID:** H.1
**Severity:** CRITICAL
**Description:** Verifies that container secrets are injected via
AWS Secrets Manager or SSM Parameter Store (ECS `secrets` block
with `valueFrom`), not hardcoded in environment variables.

**Why This Check Is Critical:**
(Same rationale as B.7 - this is the compliance-oriented view
of the same underlying check, ensuring all frameworks can
reference it consistently.)

**boto3 API Calls:**
- (Same as B.7 - evaluated per task definition)

---

### H.2 - ECR Image Scanning Enabled

**Check ID:** H.2
**Severity:** HIGH
**Description:** Verifies that ECR repositories used by container
tasks have image scanning enabled (basic or enhanced scanning
via Inspector).

**Why This Check Is Critical:**
Container images may contain known CVEs in OS packages,
application dependencies, or base image layers. Without scanning,
vulnerable images are deployed to production undetected. Enhanced
scanning via Inspector provides continuous monitoring and richer
vulnerability intelligence.

**boto3 API Calls:**
- `ecr.describe_repositories()`
- Check `imageScanningConfiguration.scanOnPush == true`
- `ecr.describe_registry()` for registry-level scan configuration

---

### H.3 - ECR Image Tag Immutability

**Check ID:** H.3
**Severity:** MEDIUM
**Description:** Verifies that ECR repositories have image tag
immutability enabled to prevent image tag overwriting.

**Why This Check Is Critical:**
Without tag immutability, a `latest` or versioned tag can be
overwritten with a malicious image. An attacker with ECR push
access can replace a trusted image, and all subsequent pulls
will retrieve the compromised version. Immutable tags ensure
each tag points to exactly one image digest forever.

**boto3 API Calls:**
- `ecr.describe_repositories()`
- Check `imageTagMutability == "IMMUTABLE"`

---

### H.4 - In-Transit Encryption

**Check ID:** H.4
**Severity:** MEDIUM
**Description:** Verifies that container services use TLS for
inter-service and external communication. Checks ECS Service
Connect TLS configuration and EKS endpoint encryption.

**Why This Check Is Critical:**
Unencrypted network traffic between containers or between
containers and external services can be intercepted by an attacker
with network access. TLS ensures data confidentiality and integrity
in transit.

**boto3 API Calls:**
- ECS: Check service `serviceConnectConfiguration` for TLS
- EKS: Check cluster endpoint configuration (always TLS by default)

---

## Scoring Summary

| Check | Condition | Deduction | Severity |
|-------|-----------|-----------|----------|
| A.1 | Container Insights not enabled | -5 | MEDIUM |
| A.2 | Execute Command logging not configured | -10 | HIGH |
| A.3 | No KMS encryption on cluster | -5 | MEDIUM |
| A.4 | No capacity provider strategy | -2 | LOW |
| A.5 | No Service Connect namespace | -2 | LOW |
| B.1 | Privileged containers found | -20 | CRITICAL |
| B.2 | Root user containers found | -15 | HIGH |
| B.3 | Read-only root filesystem not enabled | -10 | HIGH |
| B.4 | Dangerous Linux capabilities found | -10 | HIGH |
| B.5 | Non-awsvpc network mode | -15 | HIGH |
| B.6 | Missing container logging | -10 | HIGH |
| B.7 | Secrets in environment variables | -20 | CRITICAL |
| B.8 | No resource limits | -5 | MEDIUM |
| B.9 | PID mode set to host | -10 | HIGH |
| B.10 | No execution role configured | -10 | HIGH |
| C.1 | ECS Exec enabled without logging | -5 | MEDIUM |
| C.2 | Public IP auto-assigned to tasks | -15 | HIGH |
| C.3 | No deployment circuit breaker | -5 | MEDIUM |
| C.4 | Outdated Fargate platform version | -5 | MEDIUM |
| C.5 | Missing security groups | -10 | HIGH |
| D.1 | Public K8s API endpoint unrestricted | -20 | CRITICAL |
| D.2 | Private endpoint not enabled | -10 | HIGH |
| D.3 | No secrets encryption (KMS) | -15 | HIGH |
| D.4 | Incomplete control plane logging | -10 | HIGH |
| D.5 | Unsupported Kubernetes version | -20 | CRITICAL |
| D.6 | Missing cluster security group | -5 | MEDIUM |
| D.7 | Missing managed add-ons | -5 | MEDIUM |
| D.8 | Fargate profile misconfigured | -5 | MEDIUM |
| E.1 | Unrestricted SSH to nodes | -15 | HIGH |
| E.2 | Unencrypted node group disks | -10 | HIGH |
| E.3 | Insecure AMI type | -5 | MEDIUM |
| E.4 | No launch template | -2 | LOW |
| F.1 | Task/execution role not separated | -10 | HIGH |
| F.2 | Admin/wildcard IAM role | -20 | CRITICAL |
| F.3 | No OIDC provider (IRSA) | -15 | HIGH |
| F.4 | Execution policy on task role | -5 | MEDIUM |
| F.5 | Cluster role overly permissive | -5 | MEDIUM |
| G.3 | GuardDuty not enabled | -10 | HIGH |
| G.4 | No VPC Flow Logs | -5 | MEDIUM |
| H.2 | ECR scanning not enabled | -10 | HIGH |
| H.3 | ECR tag mutability enabled | -5 | MEDIUM |
| H.4 | No in-transit encryption | -5 | MEDIUM |

**Shared references (no separate deductions):**
- G.1 (Container-Level Logging) shares evaluation with B.6.
  Compliance lambdas for G.1 read the `container_logging` key.
- G.2 (Container Insights) shares evaluation with A.1.
  Compliance lambdas for G.2 read the `container_insights` key.
- H.1 (Secrets via Secrets Manager) shares evaluation with B.7.
  Compliance lambdas for H.1 read the `secrets_in_env` key.
  H.1 applies only to ECS clusters (task definitions).

**Score floor:** `max(0, score)`. Clusters with `scan_error: True`
have `security_score: None` and are excluded from averages.

**Score Interpretation:**
| Range | Rating |
|-------|--------|
| 90-100 | Excellent |
| 70-89 | Good |
| 50-69 | Needs Improvement |
| 0-49 | Critical |
