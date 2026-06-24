# ECS/EKS Security Scanner - Comprehensive Remediation Guide

This guide provides step-by-step remediation instructions for all security vulnerabilities detected by the ECS/EKS Security Scanner. Each vulnerability includes remediation steps using AWS Console, AWS CLI, and Python boto3 methods. Check IDs (A.1, B.2, ...) match [security-checks.md](security-checks.md); framework mappings are in [compliance.md](compliance.md).

> **Note on task definitions**: ECS task definitions are **immutable**. You remediate a task-definition finding by registering a **new revision** with the corrected setting and updating the service to use it. The CLI/boto3 examples reflect this.

> **Note on severities**: each finding's `Severity:` is the **scanner's scoring severity**. Where a finding also cites an AWS FSBP control (for example `ECS.20`, `EKS.3`), the official Security Hub severity of that control may differ - see [compliance.md](compliance.md).

> **Note on compliance tokens**: the `Compliance:` line on each finding lists indicative framework references for orientation. The authoritative, per-check control mappings are maintained in [compliance.md](compliance.md).

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|------------------|
| ECS Security | [Security in Amazon ECS](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security.html) |
| EKS Security | [Security in Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/security.html) |
| ECS Best Practices | [ECS Best Practices Guide](https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/) |
| EKS Best Practices | [EKS Best Practices Guide](https://aws.github.io/aws-eks-best-practices/) |
| Task Definition Parameters | [Task Definition Parameters](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html) |
| EKS Cluster Endpoint Access | [Cluster Endpoint Access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html) |
| EKS Secrets Encryption | [Envelope Encryption](https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html) |
| ECR Image Scanning | [Image Scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html) |
| AWS CLI ECS / EKS | [ECS](https://docs.aws.amazon.com/cli/latest/reference/ecs/) / [EKS](https://docs.aws.amazon.com/cli/latest/reference/eks/) |
| Boto3 ECS / EKS | [ECS](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html) / [EKS](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html) |

## Table of Contents

1. [ECS Cluster Security](#ecs-cluster-security)
2. [ECS Task Definition Security](#ecs-task-definition-security)
3. [ECS Service Security](#ecs-service-security)
4. [EKS Cluster Security](#eks-cluster-security)
5. [EKS Node Group Security](#eks-node-group-security)
6. [IAM & Access Control](#iam--access-control)
7. [Logging & Monitoring](#logging--monitoring)
8. [Data Protection](#data-protection)
9. [Quick Reference Commands](#quick-reference-commands)
10. [Additional Notes](#additional-notes)

---

## ECS Cluster Security

### 1. Enable Container Insights

**Issue**: ECS cluster does not have Container Insights enabled (checks A.1, G.2)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP ECS.12, PCI-DSS 10.x, NIST AU-6, SI-4, ISO 27001 A.8.16

Container Insights collects task/service-level metrics and logs needed to detect resource abuse, cryptomining, and anomalies. (G.2 is the compliance-oriented view of this same setting.)

#### AWS Console
1. **ECS Console** -> **Clusters** -> select the cluster -> **Update cluster**
2. Under **Monitoring**, enable **Container Insights** (or **Container Insights with enhanced observability**)
3. **Update**

#### AWS CLI
```bash
aws ecs update-cluster-settings \
  --cluster my-cluster \
  --settings name=containerInsights,value=enabled
```

#### Python boto3
```python
import boto3

def enable_container_insights(cluster):
    ecs = boto3.client('ecs')
    ecs.update_cluster_settings(
        cluster=cluster,
        settings=[{'name': 'containerInsights', 'value': 'enabled'}])
    print(f"Container Insights enabled on {cluster}.")

# Usage
# enable_container_insights('my-cluster')
```

---

### 2. Configure Execute Command Logging

**Issue**: ECS cluster has ECS Exec without audit logging configured (check A.2)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 10.2.x, HIPAA 164.312(b), NIST AU-2, AU-12, ISO 27001 A.8.15

ECS Exec gives interactive shell access into containers. Route the session audit to CloudWatch Logs or S3 so exec activity is recorded.

#### AWS Console
1. Execute Command logging is set on the cluster configuration via the API/CLI
2. Create a CloudWatch log group (and optionally an S3 bucket) for the session logs
3. Recreate or update the cluster with an `executeCommandConfiguration` that points to that log group (see CLI)

#### AWS CLI
```bash
# Provide an execute-command configuration with logging != NONE
aws ecs update-cluster \
  --cluster my-cluster \
  --configuration '{
    "executeCommandConfiguration": {
      "logging": "OVERRIDE",
      "logConfiguration": {
        "cloudWatchLogGroupName": "/ecs/exec-audit",
        "cloudWatchEncryptionEnabled": true
      }
    }
  }'
```

#### Python boto3
```python
import boto3

def configure_exec_logging(cluster, log_group='/ecs/exec-audit'):
    ecs = boto3.client('ecs')
    ecs.update_cluster(
        cluster=cluster,
        configuration={
            'executeCommandConfiguration': {
                'logging': 'OVERRIDE',
                'logConfiguration': {
                    'cloudWatchLogGroupName': log_group,
                    'cloudWatchEncryptionEnabled': True,
                },
            }
        })
    print(f"Execute Command logging -> {log_group} on {cluster}.")

# Usage
# configure_exec_logging('my-cluster')
```

---

### 3. Encrypt the ECS Cluster With KMS

**Issue**: ECS cluster managed storage is not encrypted with a customer-managed KMS key (check A.3)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 3.5.1, HIPAA 164.312(a)(2)(iv), NIST SC-28, ISO 27001 A.8.24

A customer-managed KMS key on managed storage gives you control over rotation and access. Set it in the cluster's managed storage configuration.

#### AWS Console
1. **ECS Console** -> **Clusters** -> **Create cluster** (or update) -> **Encryption**
2. Under **Managed storage**, choose a **customer-managed KMS key**
3. Save

#### AWS CLI
```bash
aws ecs update-cluster \
  --cluster my-cluster \
  --configuration '{
    "managedStorageConfiguration": {
      "kmsKeyId": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
    }
  }'
```

#### Python boto3
```python
import boto3

def set_cluster_kms(cluster, kms_key_arn):
    ecs = boto3.client('ecs')
    ecs.update_cluster(
        cluster=cluster,
        configuration={'managedStorageConfiguration': {'kmsKeyId': kms_key_arn}})
    print(f"Managed-storage KMS key set on {cluster}. "
          f"Existing tasks must be redeployed to pick up the new key.")

# Usage
# set_cluster_kms('my-cluster', 'arn:aws:kms:us-east-1:123456789012:key/abcd')
```

---

### 4. Set a Default Capacity Provider Strategy

**Issue**: ECS cluster has no default capacity provider strategy (check A.4)
**Severity**: LOW
**Compliance**: AWS-FSBP ECS baseline, NIST CM-6, ISO 27001 A.8.9

A default strategy ensures tasks launch on the intended infrastructure (for example Fargate) rather than falling back to unintended compute.

#### AWS Console
1. **ECS Console** -> **Clusters** -> select cluster -> **Update cluster**
2. Under **Infrastructure**, set the **default capacity provider strategy** (for example `FARGATE`)
3. **Update**

#### AWS CLI
```bash
aws ecs put-cluster-capacity-providers \
  --cluster my-cluster \
  --capacity-providers FARGATE FARGATE_SPOT \
  --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1
```

#### Python boto3
```python
import boto3

def set_default_capacity_provider(cluster):
    ecs = boto3.client('ecs')
    ecs.put_cluster_capacity_providers(
        cluster=cluster,
        capacityProviders=['FARGATE', 'FARGATE_SPOT'],
        defaultCapacityProviderStrategy=[
            {'capacityProvider': 'FARGATE', 'weight': 1}])
    print(f"Default capacity provider strategy set on {cluster}.")

# Usage
# set_default_capacity_provider('my-cluster')
```

---

### 5. Configure a Service Connect Namespace

**Issue**: ECS cluster has no Service Connect default namespace (check A.5)
**Severity**: LOW
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 4.2.1, NIST SC-8, ISO 27001 A.8.24

A Service Connect namespace enables service discovery with mutual TLS between services, avoiding unencrypted inter-service traffic.

#### AWS Console
1. **ECS Console** -> **Clusters** -> select cluster -> **Update cluster**
2. Under **Service Connect**, set a **default namespace** (creates an AWS Cloud Map namespace)
3. **Update**

#### AWS CLI
```bash
aws ecs update-cluster \
  --cluster my-cluster \
  --service-connect-defaults namespace=internal.my-cluster
```

#### Python boto3
```python
import boto3

def set_service_connect_namespace(cluster, namespace):
    ecs = boto3.client('ecs')
    ecs.update_cluster(cluster=cluster,
                       serviceConnectDefaults={'namespace': namespace})
    print(f"Service Connect namespace {namespace} set on {cluster}.")

# Usage
# set_service_connect_namespace('my-cluster', 'internal.my-cluster')
```

---

## ECS Task Definition Security

> For every check in this section, remediation means registering a **new task-definition revision** with the corrected field, then updating the service to the new revision. When you build the revision from `describe-task-definition` output, you must first **strip the read-only fields** (`taskDefinitionArn`, `revision`, `status`, `requiresAttributes`, `compatibilities`, `registeredAt`, `registeredBy`, `deregisteredAt`) or `register-task-definition` rejects them, and you should re-pin the service to the **explicit new revision ARN**, not the bare family name.

### 6. Remove Privileged Containers

**Issue**: A container definition uses `privileged: true` (check B.1)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP ECS.4, PCI-DSS 2.2.x, NIST AC-6(1), CM-7, ISO 27001 A.8.2

A privileged container has root-level host kernel/device access; a container escape gives full host control. Remove `privileged` and grant only the specific Linux capabilities actually required.

#### AWS Console
1. **ECS Console** -> **Task definitions** -> select the family -> **Create new revision**
2. Edit the container -> under **Docker configuration**, ensure **Privileged** is **off**
3. **Create** the revision and update the service to use it

#### AWS CLI
```bash
# Pull the current definition and strip the read-only fields that
# register-task-definition rejects (this same pattern applies to R7-R15):
aws ecs describe-task-definition --task-definition myapp --query 'taskDefinition' \
  | jq 'del(.taskDefinitionArn,.revision,.status,.requiresAttributes,.compatibilities,.registeredAt,.registeredBy,.deregisteredAt)' > td.json
# edit td.json: set "privileged": false on each container, then register and
# capture the explicit new revision ARN:
TD=$(aws ecs register-task-definition --cli-input-json file://td.json \
  --query 'taskDefinition.taskDefinitionArn' --output text)
aws ecs update-service --cluster my-cluster --service myapp --task-definition "$TD"
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def deprivilege_task_def(family):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    for c in td['containerDefinitions']:
        c['privileged'] = False
    new = {k: v for k, v in td.items() if k not in STRIP}
    resp = ecs.register_task_definition(**new)
    print(f"Registered {resp['taskDefinition']['taskDefinitionArn']} "
          f"with privileged=false.")

# Usage
# deprivilege_task_def('myapp')
```

---

### 7. Run Containers as a Non-Root User

**Issue**: A container runs as root (no `user`, or UID 0 / "root") (check B.2)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS.20, PCI-DSS 2.2.x, NIST AC-6, ISO 27001 A.8.2

Set a non-root `user` so a container compromise is confined to application-level access.

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Edit the container -> set **User** to a non-root value (for example `1000` or `appuser`)
3. **Create** the revision and update the service

#### AWS CLI
```bash
# In the registered task definition JSON, set "user": "1000" on each
# container, then register a new revision:
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def set_nonroot_user(family, user='1000'):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    for c in td['containerDefinitions']:
        c['user'] = user
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision with user={user}.")

# Usage
# set_nonroot_user('myapp', '1000')
```

---

### 8. Enable a Read-Only Root Filesystem

**Issue**: A container does not set `readonlyRootFilesystem: true` (check B.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS.5, PCI-DSS 2.2.x, NIST CM-7, SI-7, ISO 27001 A.8.2

A read-only root filesystem blocks malware persistence and binary tampering. Mount writable paths explicitly as tmpfs/volumes.

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Edit the container -> enable **Read only root file system**
3. Add tmpfs/volume mounts for any paths the app must write
4. **Create** the revision

#### AWS CLI
```bash
# Set "readonlyRootFilesystem": true per container, then:
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def set_readonly_rootfs(family):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    for c in td['containerDefinitions']:
        c['readonlyRootFilesystem'] = True
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision with read-only root filesystem.")

# Usage
# set_readonly_rootfs('myapp')
```

---

### 9. Drop Dangerous Linux Capabilities

**Issue**: A container does not drop dangerous Linux capabilities (or adds them) (check B.4)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 2.2.x, NIST AC-6(1), CM-7, ISO 27001 A.8.2

Drop `ALL` and add back only the capabilities the workload genuinely needs; never add `SYS_ADMIN`, `NET_ADMIN`, or `NET_RAW` unless strictly required.

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Edit the container -> **Linux parameters** -> **Capabilities**: set **Drop** = `ALL`, add back only what is needed
3. **Create** the revision

#### AWS CLI
```bash
# Set linuxParameters.capabilities.drop = ["ALL"] (add back only as needed),
# then register a new revision:
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def drop_capabilities(family, keep=None):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    for c in td['containerDefinitions']:
        lp = c.setdefault('linuxParameters', {})
        lp['capabilities'] = {'drop': ['ALL'], 'add': keep or []}
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision dropping ALL capabilities.")

# Usage
# drop_capabilities('myapp')
```

---

### 10. Use the awsvpc Network Mode

**Issue**: Task definition uses `host`, `bridge`, or `none` instead of `awsvpc` (check B.5)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS.17, PCI-DSS 1.3.x, NIST SC-7, AC-4, ISO 27001 A.8.20

`awsvpc` gives each task its own ENI and security group, enabling per-task network isolation. `host` shares the host network namespace (no isolation).

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Set **Network mode** to **awsvpc**
3. Update the service network configuration (subnets + security groups) accordingly
4. **Create** the revision

#### AWS CLI
```bash
# Set "networkMode": "awsvpc" in the task definition, then:
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def set_awsvpc(family):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    td['networkMode'] = 'awsvpc'
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision with awsvpc network mode.")

# Usage
# set_awsvpc('myapp')
```

---

### 11. Configure Container Logging

**Issue**: A container has no `logConfiguration` / log driver (checks B.6, G.1)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS.9, PCI-DSS 10.2.x, HIPAA 164.312(b), NIST AU-2, AU-6, ISO 27001 A.8.15

Without a log driver, container stdout/stderr is lost. Use `awslogs` (CloudWatch) or `awsfirelens`. (G.1 is the compliance view of this same setting.)

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Edit the container -> **Logging** -> enable **Use log collection** (Amazon CloudWatch / awslogs)
3. **Create** the revision

#### AWS CLI
```bash
# Add logConfiguration to each container, then register a new revision:
aws ecs register-task-definition --cli-input-json file://td.json
# Example logConfiguration block:
#   "logConfiguration": {
#     "logDriver": "awslogs",
#     "options": {
#       "awslogs-group": "/ecs/myapp",
#       "awslogs-region": "us-east-1",
#       "awslogs-stream-prefix": "myapp"
#     }
#   }
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def add_awslogs(family, region='us-east-1'):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    for c in td['containerDefinitions']:
        c['logConfiguration'] = {
            'logDriver': 'awslogs',
            'options': {
                'awslogs-group': f"/ecs/{family}",
                'awslogs-region': region,
                'awslogs-stream-prefix': c['name'],
            }}
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision with awslogs logging.")

# Usage
# add_awslogs('myapp')
```

---

### 12. Move Secrets Out of Environment Variables

**Issue**: A container has plaintext secrets in environment variables (checks B.7, H.1)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP ECS.8, PCI-DSS 8.3.x, HIPAA 164.312(a)(2)(i), GDPR Art.32, NIST IA-5, SC-12, ISO 27001 A.5.17

Plaintext env vars are visible in the console, task metadata, and `docker inspect`. Use the `secrets` block with `valueFrom` referencing Secrets Manager or SSM Parameter Store. (H.1 is the compliance view of this same setting.)

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Edit the container -> remove the plaintext **Environment variables**
3. Under **Secrets**, add entries that reference **Secrets Manager** or **SSM Parameter Store** ARNs
4. **Create** the revision

#### AWS CLI
```bash
# Store the secret first
aws secretsmanager create-secret --name myapp/db-password \
  --secret-string 'S3cr3t!'

# In the task definition, replace the plaintext env var with a secrets entry:
#   "secrets": [{
#     "name": "DB_PASSWORD",
#     "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:myapp/db-password"
#   }]
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

SECRET_NAME_HINTS = ('PASSWORD', 'SECRET', 'TOKEN', 'API_KEY', 'PRIVATE_KEY',
                     'CREDENTIALS', 'CONNECTION_STRING')
STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def find_env_secrets(family):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    hits = []
    for c in td['containerDefinitions']:
        for env in c.get('environment', []):
            if any(h in env['name'].upper() for h in SECRET_NAME_HINTS):
                hits.append((c['name'], env['name']))
    for cname, key in hits:
        print(f"CRITICAL plaintext secret {key} in container {cname} "
              f"-> migrate to a 'secrets' valueFrom entry")
    return hits

# Usage
# find_env_secrets('myapp')
```

---

### 13. Define CPU and Memory Resource Limits

**Issue**: Task definition has no CPU/memory limits at task or container level (check B.8)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS baseline, NIST SC-6, ISO 27001 A.8.6

Resource limits prevent a single container from starving the host (a denial-of-service vector) and enable accurate accounting.

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Set **Task size** (CPU/memory) and/or per-container **CPU units** and **Memory limits**
3. **Create** the revision

#### AWS CLI
```bash
# Set task-level "cpu"/"memory" (and/or per-container), then:
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def set_resource_limits(family, cpu='256', memory='512'):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    td['cpu'], td['memory'] = cpu, memory
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision with cpu={cpu}, memory={memory}.")

# Usage
# set_resource_limits('myapp', '256', '512')
```

---

### 14. Disable Host PID Mode

**Issue**: Task definition sets `pidMode: host` (check B.9)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS.3, PCI-DSS 2.2.x, NIST AC-6, SC-7, ISO 27001 A.8.2

Host PID mode lets a container see and signal all host processes (including other containers and the ECS agent), and read their environment. Remove `pidMode: host`.

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Under **Task configuration**, ensure **PID mode** is not set to **host** (leave unset or set to `task`)
3. **Create** the revision

#### AWS CLI
```bash
# Remove "pidMode": "host" from the task definition, then:
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def clear_host_pid(family):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    td.pop('pidMode', None)
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision without host PID mode.")

# Usage
# clear_host_pid('myapp')
```

---

### 15. Configure a Task Execution Role

**Issue**: Task definition has no `executionRoleArn` (check B.10)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 7.2.x, NIST AC-6, IA-2, ISO 27001 A.5.15

The execution role lets the ECS agent pull images and ship logs without falling back to the broader EC2 instance role. Attach a dedicated execution role with the managed `AmazonECSTaskExecutionRolePolicy`.

#### AWS Console
1. Create an execution role trusting `ecs-tasks.amazonaws.com` with `AmazonECSTaskExecutionRolePolicy`
2. **ECS Console** -> **Task definitions** -> **Create new revision** -> set **Task execution role**
3. **Create** the revision

#### AWS CLI
```bash
# Create the execution role
cat > ecs-tasks-trust.json << 'EOF'
{ "Version": "2012-10-17", "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ecs-tasks.amazonaws.com" },
    "Action": "sts:AssumeRole" }] }
EOF
aws iam create-role --role-name ecsTaskExecutionRole \
  --assume-role-policy-document file://ecs-tasks-trust.json
aws iam attach-role-policy --role-name ecsTaskExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Set "executionRoleArn" in the task definition, then register a new revision.
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

STRIP = {'taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
         'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt'}

def set_execution_role(family, role_arn):
    ecs = boto3.client('ecs')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    td['executionRoleArn'] = role_arn
    new = {k: v for k, v in td.items() if k not in STRIP}
    ecs.register_task_definition(**new)
    print(f"Registered {family} revision with execution role {role_arn}.")

# Usage
# set_execution_role('myapp', 'arn:aws:iam::123456789012:role/ecsTaskExecutionRole')
```

---

## ECS Service Security

### 16. Restrict and Log ECS Exec on Services

**Issue**: A service enables ECS Exec without cluster Execute Command logging (check C.1)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 10.2.x, NIST AU-2, AC-17, ISO 27001 A.8.15

If a service needs ECS Exec, ensure the cluster has Execute Command logging (remediation 2); otherwise disable it.

#### AWS Console
1. **ECS Console** -> **Clusters** -> service -> **Update**
2. Turn off **Enable execute command** unless it is required
3. If required, confirm the cluster has Execute Command logging configured (remediation 2)

#### AWS CLI
```bash
# Disable ECS Exec on a service
aws ecs update-service --cluster my-cluster --service myapp \
  --no-enable-execute-command --force-new-deployment
```

#### Python boto3
```python
import boto3

def disable_ecs_exec(cluster, service):
    ecs = boto3.client('ecs')
    ecs.update_service(cluster=cluster, service=service,
                       enableExecuteCommand=False, forceNewDeployment=True)
    print(f"ECS Exec disabled on {service}.")

# Usage
# disable_ecs_exec('my-cluster', 'myapp')
```

---

### 17. Disable Auto-Assigned Public IPs

**Issue**: A service/task set auto-assigns a public IP (check C.2)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS.2, ECS.16, PCI-DSS 1.3.1, NIST SC-7, AC-4, ISO 27001 A.8.20

Tasks with public IPs are reachable from the internet. Run them in private subnets and set `assignPublicIp=DISABLED`, fronted by a load balancer/NAT.

#### AWS Console
1. **ECS Console** -> **Clusters** -> service -> **Update**
2. Under **Networking**, set **Public IP** to **Turned off** and use private subnets
3. **Update**

#### AWS CLI
```bash
aws ecs update-service \
  --cluster my-cluster --service myapp \
  --network-configuration 'awsvpcConfiguration={subnets=[subnet-private1,subnet-private2],securityGroups=[sg-app],assignPublicIp=DISABLED}' \
  --force-new-deployment
```

#### Python boto3
```python
import boto3

def disable_public_ip(cluster, service, subnets, security_groups):
    ecs = boto3.client('ecs')
    ecs.update_service(
        cluster=cluster, service=service,
        networkConfiguration={'awsvpcConfiguration': {
            'subnets': subnets, 'securityGroups': security_groups,
            'assignPublicIp': 'DISABLED'}},
        forceNewDeployment=True)
    print(f"Public IP disabled on {service}.")

# Usage
# disable_public_ip('my-cluster', 'myapp', ['subnet-a'], ['sg-app'])
```

---

### 18. Enable the Deployment Circuit Breaker

**Issue**: A service has no deployment circuit breaker with rollback (check C.3)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP ECS baseline, NIST CM-3, SI-7, ISO 27001 A.8.32

The circuit breaker automatically rolls back failed deployments, restoring the known-good configuration.

#### AWS Console
1. **ECS Console** -> **Clusters** -> service -> **Update**
2. Under **Deployment options**, enable **Use deployment circuit breaker** and **Rollback on failure**
3. **Update**

#### AWS CLI
```bash
aws ecs update-service \
  --cluster my-cluster --service myapp \
  --deployment-configuration 'deploymentCircuitBreaker={enable=true,rollback=true}' \
  --force-new-deployment
# (the circuit breaker config applies to the next deployment; --force-new-deployment
#  rolls it out now)
```

#### Python boto3
```python
import boto3

def enable_circuit_breaker(cluster, service):
    ecs = boto3.client('ecs')
    ecs.update_service(
        cluster=cluster, service=service,
        deploymentConfiguration={
            'deploymentCircuitBreaker': {'enable': True, 'rollback': True}})
    print(f"Deployment circuit breaker enabled on {service}.")

# Usage
# enable_circuit_breaker('my-cluster', 'myapp')
```

---

### 19. Keep the Fargate Platform Version Current

**Issue**: A Fargate service runs an outdated platform version (check C.4)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP ECS.10, PCI-DSS 6.3.3, NIST SI-2, RA-5, ISO 27001 A.8.8

Newer Fargate platform versions include security patches and ephemeral-storage encryption. Set the platform version to `LATEST` and redeploy.

#### AWS Console
1. **ECS Console** -> **Clusters** -> service -> **Update**
2. Set **Platform version** to **LATEST**
3. Enable **Force new deployment** and **Update**

#### AWS CLI
```bash
aws ecs update-service \
  --cluster my-cluster --service myapp \
  --platform-version LATEST \
  --force-new-deployment
```

#### Python boto3
```python
import boto3

def update_platform_version(cluster, service):
    ecs = boto3.client('ecs')
    ecs.update_service(cluster=cluster, service=service,
                       platformVersion='LATEST', forceNewDeployment=True)
    print(f"{service} set to Fargate platform version LATEST.")

# Usage
# update_platform_version('my-cluster', 'myapp')
```

---

### 20. Attach Security Groups to Services

**Issue**: An awsvpc service has no security groups configured (check C.5)
**Severity**: HIGH
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 1.3.x, NIST SC-7, AC-4, ISO 27001 A.8.20

Security groups are the per-task firewall in awsvpc mode. Attach a least-privilege security group to the service network configuration.

#### AWS Console
1. **ECS Console** -> **Clusters** -> service -> **Update**
2. Under **Networking**, select one or more **security groups** that restrict inbound/outbound traffic
3. **Update**

#### AWS CLI
```bash
aws ecs update-service \
  --cluster my-cluster --service myapp \
  --network-configuration 'awsvpcConfiguration={subnets=[subnet-private1],securityGroups=[sg-restrictive],assignPublicIp=DISABLED}' \
  --force-new-deployment
```

#### Python boto3
```python
import boto3

def attach_security_groups(cluster, service, subnets, security_groups):
    ecs = boto3.client('ecs')
    ecs.update_service(
        cluster=cluster, service=service,
        networkConfiguration={'awsvpcConfiguration': {
            'subnets': subnets, 'securityGroups': security_groups,
            'assignPublicIp': 'DISABLED'}},
        forceNewDeployment=True)
    print(f"Security groups {security_groups} attached to {service}.")

# Usage
# attach_security_groups('my-cluster', 'myapp', ['subnet-a'], ['sg-restrictive'])
```

---

## EKS Cluster Security

### 21. Restrict the Public API Endpoint

**Issue**: The EKS API endpoint is public and unrestricted (`0.0.0.0/0`) (check D.1)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP EKS.1, CIS EKS 5.4.1, PCI-DSS 1.3.1, NIST AC-4, SC-7, ISO 27001 A.8.20

Expose the control plane only privately, or restrict public access to known CIDRs.

#### AWS Console
1. **EKS Console** -> select the cluster -> **Networking** -> **Manage endpoint access**
2. Choose **Private**, or keep **Public and private** but set **Advanced settings** -> specific CIDRs (never `0.0.0.0/0`)
3. **Save changes**

#### AWS CLI
```bash
# Private-only, or public restricted to a known CIDR
aws eks update-cluster-config --name my-cluster \
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=203.0.113.0/24,endpointPrivateAccess=true
```

#### Python boto3
```python
import boto3

def restrict_api_endpoint(cluster, allowed_cidrs):
    eks = boto3.client('eks')
    eks.update_cluster_config(
        name=cluster,
        resourcesVpcConfig={
            'endpointPublicAccess': True,
            'publicAccessCidrs': allowed_cidrs,
            'endpointPrivateAccess': True})
    print(f"{cluster} public endpoint restricted to {allowed_cidrs}.")

# Usage
# restrict_api_endpoint('my-cluster', ['203.0.113.0/24'])
```

---

### 22. Enable Private Endpoint Access

**Issue**: The EKS cluster does not have private endpoint access enabled (check D.2)
**Severity**: HIGH
**Compliance**: CIS EKS 5.4.2, PCI-DSS 1.3.x, NIST SC-7, AC-4, ISO 27001 A.8.20

Enabling the private endpoint keeps node-to-control-plane traffic inside the VPC.

#### AWS Console
1. **EKS Console** -> cluster -> **Networking** -> **Manage endpoint access**
2. Enable **Private access**
3. **Save changes**

#### AWS CLI
```bash
aws eks update-cluster-config --name my-cluster \
  --resources-vpc-config endpointPrivateAccess=true
```

#### Python boto3
```python
import boto3

def enable_private_endpoint(cluster):
    eks = boto3.client('eks')
    eks.update_cluster_config(
        name=cluster, resourcesVpcConfig={'endpointPrivateAccess': True})
    print(f"Private endpoint enabled on {cluster}.")

# Usage
# enable_private_endpoint('my-cluster')
```

---

### 23. Enable Kubernetes Secrets KMS Encryption

**Issue**: EKS cluster secrets are not encrypted with a KMS key (check D.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP EKS.3, CIS EKS 5.3.1, PCI-DSS 3.5.1, HIPAA 164.312(a)(2)(iv), NIST SC-28, ISO 27001 A.8.24

Enable envelope encryption so Kubernetes secrets in etcd are encrypted with a customer-managed KMS key. This can be enabled on an existing cluster but cannot be removed afterward.

#### AWS Console
1. **EKS Console** -> cluster -> **Overview** / **Secrets encryption** -> **Enable**
2. Choose a customer-managed **KMS key**
3. Confirm (this is a one-way enablement)

#### AWS CLI
```bash
aws eks associate-encryption-config \
  --cluster-name my-cluster \
  --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"}}]'
```

#### Python boto3
```python
import boto3

def enable_secrets_encryption(cluster, key_arn):
    eks = boto3.client('eks')
    eks.associate_encryption_config(
        clusterName=cluster,
        encryptionConfig=[{'resources': ['secrets'],
                           'provider': {'keyArn': key_arn}}])
    print(f"Secrets KMS encryption enabling on {cluster} (one-way).")

# Usage
# enable_secrets_encryption('my-cluster', 'arn:aws:kms:us-east-1:123456789012:key/abcd')
```

---

### 24. Enable All Control Plane Log Types

**Issue**: Not all 5 EKS control plane log types are enabled (check D.4)
**Severity**: HIGH
**Compliance**: AWS-FSBP EKS.8, CIS EKS 2.1.1, PCI-DSS 10.2.x, HIPAA 164.312(b), NIST AU-2, AU-12, ISO 27001 A.8.15

Enable `api`, `audit`, `authenticator`, `controllerManager`, and `scheduler` logs so API activity and authentication attempts are recorded.

#### AWS Console
1. **EKS Console** -> cluster -> **Observability** / **Logging** -> **Manage logging**
2. Turn on all five control plane log types
3. **Save changes**

#### AWS CLI
```bash
aws eks update-cluster-config --name my-cluster \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

#### Python boto3
```python
import boto3

def enable_all_control_plane_logs(cluster):
    eks = boto3.client('eks')
    eks.update_cluster_config(
        name=cluster,
        logging={'clusterLogging': [{
            'types': ['api', 'audit', 'authenticator',
                      'controllerManager', 'scheduler'],
            'enabled': True}]})
    print(f"All control plane log types enabled on {cluster}.")

# Usage
# enable_all_control_plane_logs('my-cluster')
```

---

### 25. Run a Supported Kubernetes Version

**Issue**: The EKS cluster runs an end-of-life Kubernetes version (check D.5)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP EKS.2, PCI-DSS 6.3.3, NIST SI-2, RA-5, ISO 27001 A.8.8

EOL versions stop receiving security patches. Upgrade to a supported version (one minor version at a time), validating workloads between upgrades.

#### AWS Console
1. **EKS Console** -> cluster -> **Overview** -> **Update version**
2. Select the next supported Kubernetes version and confirm
3. Upgrade add-ons and node groups to match, then repeat to reach a supported version

#### AWS CLI
```bash
# Upgrade the control plane one minor version at a time
aws eks update-cluster-version --name my-cluster --kubernetes-version 1.31

# Then update managed node groups to the same version
aws eks update-nodegroup-version --cluster-name my-cluster \
  --nodegroup-name ng-1 --kubernetes-version 1.31
```

#### Python boto3
```python
import boto3

def upgrade_cluster_version(cluster, target_version):
    eks = boto3.client('eks')
    eks.update_cluster_version(name=cluster, version=target_version)
    print(f"{cluster} upgrading to Kubernetes {target_version}. "
          f"Update node groups and add-ons to match.")

# Usage
# upgrade_cluster_version('my-cluster', '1.31')
```

---

### 26. Configure the Cluster Security Group

**Issue**: The EKS cluster has no dedicated cluster security group (check D.6)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EKS baseline, PCI-DSS 1.3.x, NIST SC-7, ISO 27001 A.8.20

The cluster security group governs control-plane-to-node traffic. Ensure one is associated (EKS creates a managed cluster security group by default; verify it is present and scoped).

#### AWS Console
1. **EKS Console** -> cluster -> **Networking**
2. Confirm a **Cluster security group** is present
3. Review its rules to allow only required node/control-plane traffic

#### AWS CLI
```bash
# Inspect the cluster security group
aws eks describe-cluster --name my-cluster \
  --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId'

# Review its rules
aws ec2 describe-security-groups --group-ids sg-XXXX \
  --query 'SecurityGroups[0].IpPermissions'
```

#### Python boto3
```python
import boto3

def check_cluster_security_group(cluster):
    eks = boto3.client('eks')
    cfg = eks.describe_cluster(name=cluster)['cluster']['resourcesVpcConfig']
    sg = cfg.get('clusterSecurityGroupId')
    if sg:
        print(f"OK: {cluster} cluster security group = {sg}")
    else:
        print(f"MEDIUM: {cluster} has no cluster security group")
    return sg

# Usage
# check_cluster_security_group('my-cluster')
```

---

### 27. Install Managed Add-ons

**Issue**: Critical EKS add-ons (vpc-cni, kube-proxy, coredns) are not managed (check D.7)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EKS baseline, PCI-DSS 6.3.3, NIST SI-2, CM-2, ISO 27001 A.8.8

Managed add-ons get automatic security updates from AWS. Install `vpc-cni`, `kube-proxy`, and `coredns` as managed add-ons.

#### AWS Console
1. **EKS Console** -> cluster -> **Add-ons** -> **Get more add-ons**
2. Add **Amazon VPC CNI**, **kube-proxy**, and **CoreDNS** as managed add-ons
3. Keep them updated to the recommended versions

#### AWS CLI
```bash
for addon in vpc-cni kube-proxy coredns; do
  aws eks create-addon --cluster-name my-cluster --addon-name "$addon" \
    --resolve-conflicts OVERWRITE
done
```

#### Python boto3
```python
import boto3

def install_managed_addons(cluster):
    eks = boto3.client('eks')
    for addon in ('vpc-cni', 'kube-proxy', 'coredns'):
        try:
            eks.create_addon(clusterName=cluster, addonName=addon,
                             resolveConflicts='OVERWRITE')
            print(f"Installed managed add-on {addon}.")
        except eks.exceptions.ResourceInUseException:
            print(f"{addon} already managed.")

# Usage
# install_managed_addons('my-cluster')
```

---

### 28. Secure EKS Fargate Profiles

**Issue**: EKS Fargate profile has weak subnet/selector configuration (check D.8)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EKS baseline, PCI-DSS 1.3.x, NIST SC-7, ISO 27001 A.8.20

Fargate profiles should schedule pods onto **private** subnets with well-scoped namespace/label selectors.

#### AWS Console
1. **EKS Console** -> cluster -> **Compute** -> **Fargate profiles**
2. Create/recreate the profile selecting **private subnets** and precise **namespace/label selectors**
3. Confirm

#### AWS CLI
```bash
aws eks create-fargate-profile \
  --cluster-name my-cluster \
  --fargate-profile-name app-private \
  --pod-execution-role-arn arn:aws:iam::ACCOUNT_ID:role/eksFargatePodExecutionRole \
  --subnets subnet-private1 subnet-private2 \
  --selectors '[{"namespace":"app","labels":{"tier":"backend"}}]'
```

#### Python boto3
```python
import boto3

def create_fargate_profile(cluster, name, role_arn, subnets, namespace):
    eks = boto3.client('eks')
    eks.create_fargate_profile(
        clusterName=cluster, fargateProfileName=name,
        podExecutionRoleArn=role_arn, subnets=subnets,
        selectors=[{'namespace': namespace}])
    print(f"Created Fargate profile {name} on private subnets.")

# Usage
# create_fargate_profile('my-cluster', 'app-private',
#   'arn:aws:iam::123456789012:role/eksFargatePodExecutionRole',
#   ['subnet-private1'], 'app')
```

---

## EKS Node Group Security

### 29. Restrict Node Remote Access

**Issue**: A managed node group allows unrestricted SSH (port 22 to `0.0.0.0/0`) (check E.1)
**Severity**: HIGH
**Compliance**: EKS-Hardening NODE.SSH, PCI-DSS 1.3.1, NIST AC-17, SC-7, ISO 27001 A.8.20

Prefer SSM Session Manager over SSH. If SSH is configured, scope `sourceSecurityGroups` to a bastion; never leave it open to the internet. Remote access is set at node-group creation, so remediation is to recreate the node group with scoped access.

#### AWS Console
1. **EKS Console** -> cluster -> **Compute** -> node group
2. Remote access is fixed at creation; create a replacement node group **without** a public SSH key, or with `sourceSecurityGroups` limited to a bastion
3. Migrate workloads and delete the old node group

#### AWS CLI
```bash
# Create a replacement node group with SSH limited to a bastion SG
aws eks create-nodegroup \
  --cluster-name my-cluster --nodegroup-name ng-secure \
  --node-role arn:aws:iam::ACCOUNT_ID:role/eksNodeRole \
  --subnets subnet-private1 subnet-private2 \
  --remote-access ec2SshKey=my-key,sourceSecurityGroups=sg-bastion
```

#### Python boto3
```python
import boto3

def find_open_ssh_nodegroups(cluster):
    eks = boto3.client('eks')
    flagged = []
    for ng in eks.list_nodegroups(clusterName=cluster)['nodegroups']:
        ra = eks.describe_nodegroup(clusterName=cluster, nodegroupName=ng
                                    )['nodegroup'].get('remoteAccess') or {}
        if ra.get('ec2SshKey') and not ra.get('sourceSecurityGroups'):
            flagged.append(ng)
    for ng in flagged:
        print(f"HIGH: node group {ng} has SSH key without source SG restriction")
    return flagged

# Usage
# find_open_ssh_nodegroups('my-cluster')
```

---

### 30. Encrypt Node Group Disks

**Issue**: Node group instances use unencrypted EBS volumes (check E.2)
**Severity**: HIGH
**Compliance**: AWS-FSBP EKS baseline, PCI-DSS 3.5.1, HIPAA 164.312(a)(2)(iv), NIST SC-28, ISO 27001 A.8.24

Worker-node disks hold image layers, ephemeral volumes, and cached data. Use a launch template whose block device mappings enable EBS encryption.

#### AWS Console
1. **EC2 Console** -> **Launch templates** -> create a template with **EBS encryption** enabled on the root volume
2. **EKS Console** -> create a node group that uses this launch template
3. Migrate workloads off the old node group

#### AWS CLI
```bash
# Create a launch template with an encrypted root volume
aws ec2 create-launch-template \
  --launch-template-name eks-encrypted \
  --launch-template-data '{
    "BlockDeviceMappings":[{"DeviceName":"/dev/xvda",
      "Ebs":{"Encrypted":true,"VolumeSize":50,"VolumeType":"gp3"}}]
  }'

# Use it for a new node group
aws eks create-nodegroup --cluster-name my-cluster --nodegroup-name ng-enc \
  --node-role arn:aws:iam::ACCOUNT_ID:role/eksNodeRole \
  --subnets subnet-private1 subnet-private2 \
  --launch-template name=eks-encrypted
```

#### Python boto3
```python
import boto3

def create_encrypted_launch_template(name, size=50):
    ec2 = boto3.client('ec2')
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={'BlockDeviceMappings': [{
            'DeviceName': '/dev/xvda',
            'Ebs': {'Encrypted': True, 'VolumeSize': size,
                    'VolumeType': 'gp3'}}]})
    print(f"Created encrypted launch template {name}. "
          f"Use it for a new EKS node group.")

# Usage
# create_encrypted_launch_template('eks-encrypted')
```

---

### 31. Use a Secure AMI Type

**Issue**: Node group uses a generic AMI rather than a hardened one (check E.3)
**Severity**: MEDIUM
**Compliance**: EKS-Hardening NODE.AMI, NIST CM-7, SI-2, ISO 27001 A.8.8

Bottlerocket and AL2023 are container-optimized with a minimal attack surface. Use `AL2023_*` or `BOTTLEROCKET_*` AMI types.

#### AWS Console
1. **EKS Console** -> create a node group
2. Choose an **AMI type** of **Amazon Linux 2023** or **Bottlerocket**
3. Migrate workloads from the old node group

#### AWS CLI
```bash
aws eks create-nodegroup --cluster-name my-cluster --nodegroup-name ng-bottlerocket \
  --node-role arn:aws:iam::ACCOUNT_ID:role/eksNodeRole \
  --subnets subnet-private1 subnet-private2 \
  --ami-type BOTTLEROCKET_x86_64
```

#### Python boto3
```python
import boto3

RECOMMENDED = {'AL2023_x86_64_STANDARD', 'AL2023_ARM_64_STANDARD',
               'BOTTLEROCKET_x86_64', 'BOTTLEROCKET_ARM_64'}
# A launch-template-supplied AMI reports amiType 'CUSTOM' (or absent). E.3 treats
# a custom HARDENED AMI as acceptable, so do not flag CUSTOM as a finding - review
# it manually instead.
ALLOWED_CUSTOM = {'CUSTOM', None}

def flag_insecure_ami_types(cluster):
    eks = boto3.client('eks')
    flagged = []
    for ng in eks.list_nodegroups(clusterName=cluster)['nodegroups']:
        ami = eks.describe_nodegroup(clusterName=cluster, nodegroupName=ng
                                     )['nodegroup'].get('amiType')
        if ami in ALLOWED_CUSTOM:
            print(f"REVIEW: node group {ng} uses a custom AMI - verify hardening")
            continue
        if ami not in RECOMMENDED:
            flagged.append((ng, ami))
    for ng, ami in flagged:
        print(f"MEDIUM: node group {ng} uses AMI type {ami}")
    return flagged

# Usage
# flag_insecure_ami_types('my-cluster')
```

---

### 32. Use a Launch Template for Node Groups

**Issue**: A node group does not use a launch template (check E.4)
**Severity**: LOW
**Compliance**: AWS-FSBP EKS baseline, NIST CM-2, CM-6, ISO 27001 A.8.9

Launch templates give version-controlled, auditable node configuration (encrypted volumes, IMDSv2, security groups). Recreate the node group with a launch template.

#### AWS Console
1. **EC2 Console** -> **Launch templates** -> create one with encryption, IMDSv2 required, and the desired security groups
2. **EKS Console** -> create a node group that references the launch template
3. Migrate workloads off the old node group

#### AWS CLI
```bash
# Launch template enforcing IMDSv2 and encrypted disk
aws ec2 create-launch-template --launch-template-name eks-hardened \
  --launch-template-data '{
    "MetadataOptions":{"HttpTokens":"required","HttpPutResponseHopLimit":2},
    "BlockDeviceMappings":[{"DeviceName":"/dev/xvda",
      "Ebs":{"Encrypted":true,"VolumeType":"gp3","VolumeSize":50}}]
  }'

aws eks create-nodegroup --cluster-name my-cluster --nodegroup-name ng-lt \
  --node-role arn:aws:iam::ACCOUNT_ID:role/eksNodeRole \
  --subnets subnet-private1 subnet-private2 \
  --launch-template name=eks-hardened
```

#### Python boto3
```python
import boto3

def find_nodegroups_without_launch_template(cluster):
    eks = boto3.client('eks')
    flagged = []
    for ng in eks.list_nodegroups(clusterName=cluster)['nodegroups']:
        info = eks.describe_nodegroup(clusterName=cluster, nodegroupName=ng
                                      )['nodegroup']
        if not info.get('launchTemplate'):
            flagged.append(ng)
    for ng in flagged:
        print(f"LOW: node group {ng} has no launch template")
    return flagged

# Usage
# find_nodegroups_without_launch_template('my-cluster')
```

---

## IAM & Access Control

### 33. Separate Task and Execution Roles

**Issue**: Task and execution roles are the same, or the execution policy is on the task role (checks F.1, F.4)
**Severity**: HIGH (F.1), MEDIUM (F.4)
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 7.2.x, NIST AC-6, AC-5, ISO 27001 A.5.15

The execution role (infrastructure: pull images, push logs) and the task role (application permissions) must be distinct, and `AmazonECSTaskExecutionRolePolicy` must not be on the task role.

#### AWS Console
1. **ECS Console** -> **Task definitions** -> **Create new revision**
2. Set distinct **Task role** and **Task execution role**
3. On the task role, remove **AmazonECSTaskExecutionRolePolicy** (IAM Console)
4. **Create** the revision

#### AWS CLI
```bash
# Detach the execution policy from the task role (F.4)
aws iam detach-role-policy --role-name myAppTaskRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Register a revision with distinct taskRoleArn and executionRoleArn (F.1)
aws ecs register-task-definition --cli-input-json file://td.json
```

#### Python boto3
```python
import boto3

EXEC_POLICY = ('arn:aws:iam::aws:policy/service-role/'
               'AmazonECSTaskExecutionRolePolicy')

def audit_role_separation(family):
    ecs = boto3.client('ecs')
    iam = boto3.client('iam')
    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
    task_role = td.get('taskRoleArn')
    exec_role = td.get('executionRoleArn')
    if task_role and task_role == exec_role:
        print(f"HIGH: {family} uses the same role for task and execution")
    if task_role:
        name = task_role.split('/')[-1]
        attached = iam.list_attached_role_policies(RoleName=name
                                                   )['AttachedPolicies']
        if any(p['PolicyArn'] == EXEC_POLICY for p in attached):
            print(f"MEDIUM: {family} task role has the execution policy")

# Usage
# audit_role_separation('myapp')
```

---

### 34. Remove Admin/Wildcard From Container Roles

**Issue**: An ECS task role or EKS node role has admin/wildcard permissions (check F.2)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 7.2.x, NIST AC-6(1), ISO 27001 A.8.2

A wildcard role on a container means any compromised code gets full account access. Detach admin managed policies (`AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`) and replace inline `*:*` with least privilege.

#### AWS Console
1. **IAM Console** -> open the task/node role -> **Permissions**
2. Remove **AdministratorAccess** / **PowerUserAccess** / **IAMFullAccess**
3. Rewrite inline policies to scope `Action`/`Resource` to only what the workload needs

#### AWS CLI
```bash
for p in AdministratorAccess PowerUserAccess IAMFullAccess; do
  aws iam detach-role-policy --role-name myAppTaskRole \
    --policy-arn arn:aws:iam::aws:policy/$p 2>/dev/null
done
```

#### Python boto3
```python
import boto3

ADMIN_ARNS = {
    'arn:aws:iam::aws:policy/AdministratorAccess',
    'arn:aws:iam::aws:policy/PowerUserAccess',
    'arn:aws:iam::aws:policy/IAMFullAccess',
}

def find_admin_container_roles(role_names):
    iam = boto3.client('iam')
    flagged = []
    for name in role_names:
        for p in iam.list_attached_role_policies(RoleName=name
                                                 )['AttachedPolicies']:
            if p['PolicyArn'] in ADMIN_ARNS:
                flagged.append((name, p['PolicyArn']))
        for pol in iam.list_role_policies(RoleName=name)['PolicyNames']:
            doc = iam.get_role_policy(RoleName=name, PolicyName=pol
                                      )['PolicyDocument']
            for stmt in (doc['Statement'] if isinstance(doc['Statement'], list)
                         else [doc['Statement']]):
                act = stmt.get('Action'); res = stmt.get('Resource')
                if stmt.get('Effect') == 'Allow' and '*' in (
                        act if isinstance(act, list) else [act]) and '*' in (
                        res if isinstance(res, list) else [res]):
                    flagged.append((name, f"inline:{pol}"))
    for name, why in flagged:
        print(f"CRITICAL: container role {name} -> {why}")
    return flagged

# Usage
# find_admin_container_roles(['myAppTaskRole', 'eksNodeRole'])
```

---

### 35. Configure EKS OIDC Provider (IRSA)

**Issue**: The EKS cluster has no OIDC provider for IAM Roles for Service Accounts (check F.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP EKS baseline, PCI-DSS 7.2.x, NIST AC-6, AC-5, ISO 27001 A.5.15

IRSA lets individual Kubernetes service accounts assume specific IAM roles, replacing the shared node role and enabling per-pod least privilege.

#### AWS Console
1. **EKS Console** -> cluster -> **Overview** -> copy the **OpenID Connect provider URL**
2. **IAM Console** -> **Identity providers** -> **Add provider** -> **OpenID Connect**, paste the URL, audience `sts.amazonaws.com`
3. Create IAM roles with a trust policy scoped to specific service accounts

#### AWS CLI
```bash
# Easiest with eksctl:
eksctl utils associate-iam-oidc-provider --cluster my-cluster --approve

# Or create the IAM OIDC provider directly from the cluster issuer:
ISSUER=$(aws eks describe-cluster --name my-cluster \
  --query 'cluster.identity.oidc.issuer' --output text)
aws iam create-open-id-connect-provider \
  --url "$ISSUER" --client-id-list sts.amazonaws.com \
  --thumbprint-list 9e99a48a9960b14926bb7f3b02e22da2b0ab7280
```

#### Python boto3
```python
import boto3

def check_irsa(cluster):
    eks = boto3.client('eks')
    iam = boto3.client('iam')
    issuer = eks.describe_cluster(name=cluster)['cluster'].get(
        'identity', {}).get('oidc', {}).get('issuer')
    if not issuer:
        print(f"HIGH: {cluster} has no OIDC issuer")
        return False
    providers = iam.list_open_id_connect_providers(
        )['OpenIDConnectProviderList']
    registered = any(issuer.split('https://')[-1] in p['Arn']
                     for p in providers)
    print(f"{cluster} OIDC issuer present; registered in IAM: {registered}")
    return registered

# Usage
# check_irsa('my-cluster')
```

---

### 36. Keep the EKS Cluster Role Least-Privilege

**Issue**: The EKS cluster IAM role has excessive permissions (check F.5)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP EKS baseline, PCI-DSS 7.2.x, NIST AC-6, ISO 27001 A.8.2

The cluster role should carry `AmazonEKSClusterPolicy` and nothing admin/wildcard. Remove extra admin policies.

#### AWS Console
1. **EKS Console** -> cluster -> **Overview** -> open the **Cluster IAM role**
2. In IAM, confirm only **AmazonEKSClusterPolicy** (and required service policies) are attached
3. Remove any admin/wildcard policies

#### AWS CLI
```bash
ROLE=$(aws eks describe-cluster --name my-cluster \
  --query 'cluster.roleArn' --output text | awk -F/ '{print $NF}')
aws iam list-attached-role-policies --role-name "$ROLE"
# Detach any admin policy that should not be there:
aws iam detach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
```

#### Python boto3
```python
import boto3

def audit_cluster_role(cluster):
    eks = boto3.client('eks')
    iam = boto3.client('iam')
    role_arn = eks.describe_cluster(name=cluster)['cluster']['roleArn']
    name = role_arn.split('/')[-1]
    attached = [p['PolicyArn'] for p in iam.list_attached_role_policies(
        RoleName=name)['AttachedPolicies']]
    extra = [a for a in attached
             if a.endswith(('AdministratorAccess', 'PowerUserAccess',
                            'IAMFullAccess'))]
    if extra:
        print(f"MEDIUM: cluster role {name} has excessive policies: {extra}")
    return attached

# Usage
# audit_cluster_role('my-cluster')
```

---

## Logging & Monitoring

> Container-level logging (G.1) is remediated in section 11 (B.6), and Container Insights (G.2) in section 1 (A.1). The findings below cover the remaining logging/monitoring controls.

### 37. Enable GuardDuty Container Protection

**Issue**: GuardDuty EKS/ECS protection (audit-log + runtime monitoring) is not enabled (check G.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP GuardDuty baseline, PCI-DSS 10.6.x, 11.5.x, NIST SI-4, AU-6, ISO 27001 A.8.16

GuardDuty analyzes EKS audit logs for suspicious API activity and runtime-monitors containers for reverse shells, cryptomining, and malware.

#### AWS Console
1. **GuardDuty Console** -> **Settings** / **Protection plans**
2. Enable **EKS Protection** (audit log monitoring) and **Runtime Monitoring** (EKS and ECS/Fargate)
3. Confirm the automated agent configuration

#### AWS CLI
```bash
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# EKS audit log monitoring
aws guardduty update-detector --detector-id "$DETECTOR" \
  --features '[{"Name":"EKS_AUDIT_LOGS","Status":"ENABLED"}]'

# Runtime monitoring (EKS + ECS/Fargate)
aws guardduty update-detector --detector-id "$DETECTOR" \
  --features '[{"Name":"RUNTIME_MONITORING","Status":"ENABLED","AdditionalConfiguration":[{"Name":"EKS_ADDON_MANAGEMENT","Status":"ENABLED"},{"Name":"ECS_FARGATE_AGENT_MANAGEMENT","Status":"ENABLED"}]}]'
```

#### Python boto3
```python
import boto3

def enable_guardduty_container_protection():
    gd = boto3.client('guardduty')
    detectors = gd.list_detectors()['DetectorIds']
    if not detectors:
        print("HIGH: no GuardDuty detector - enable GuardDuty first")
        return
    did = detectors[0]
    gd.update_detector(DetectorId=did, Features=[
        {'Name': 'EKS_AUDIT_LOGS', 'Status': 'ENABLED'},
        {'Name': 'RUNTIME_MONITORING', 'Status': 'ENABLED',
         'AdditionalConfiguration': [
             {'Name': 'EKS_ADDON_MANAGEMENT', 'Status': 'ENABLED'},
             {'Name': 'ECS_FARGATE_AGENT_MANAGEMENT', 'Status': 'ENABLED'}]}])
    print("GuardDuty EKS audit + runtime monitoring enabled.")

# Usage
# enable_guardduty_container_protection()
```

---

### 38. Enable VPC Flow Logs

**Issue**: VPCs used by ECS/EKS have no VPC Flow Logs (check G.4)
**Severity**: MEDIUM
**Compliance**: PCI-DSS 10.2.x, NIST AU-2, SI-4, ISO 27001 A.8.16

Flow logs capture network metadata needed to detect reconnaissance, exfiltration, and lateral movement by compromised containers.

#### AWS Console
1. **VPC Console** -> select the cluster's VPC -> **Flow logs** tab -> **Create flow log**
2. Filter **All**, destination **CloudWatch Logs** (or S3), choose/create the log group and role
3. **Create flow log**

#### AWS CLI
```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-0123456789abcdef0 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::ACCOUNT_ID:role/flowlogsRole
```

#### Python boto3
```python
import boto3

def enable_vpc_flow_logs(vpc_id, log_group, role_arn):
    ec2 = boto3.client('ec2')
    existing = ec2.describe_flow_logs(
        Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])['FlowLogs']
    if existing:
        print(f"OK: {vpc_id} already has flow logs")
        return
    ec2.create_flow_logs(
        ResourceType='VPC', ResourceIds=[vpc_id], TrafficType='ALL',
        LogDestinationType='cloud-watch-logs', LogGroupName=log_group,
        DeliverLogsPermissionArn=role_arn)
    print(f"Flow logs enabled on {vpc_id}.")

# Usage
# enable_vpc_flow_logs('vpc-0123', '/vpc/flowlogs',
#   'arn:aws:iam::123456789012:role/flowlogsRole')
```

---

## Data Protection

> Secrets via Secrets Manager / SSM (H.1) is remediated in section 12 (B.7).

### 39. Enable ECR Image Scanning

**Issue**: ECR repositories do not have image scanning enabled (check H.2)
**Severity**: HIGH
**Compliance**: CIS EKS 5.1.1, PCI-DSS 6.3.x, 11.3.x, NIST RA-5, SI-2, ISO 27001 A.8.8

Scan images for known CVEs. Enable scan-on-push per repository, or enable registry-wide enhanced scanning via Amazon Inspector.

#### AWS Console
1. **ECR Console** -> **Repositories** -> select the repo -> **Edit** -> enable **Scan on push**
2. For continuous coverage, **Private registry** -> **Scanning** -> set **Enhanced scanning** (Inspector)

#### AWS CLI
```bash
# Per-repository scan on push
aws ecr put-image-scanning-configuration \
  --repository-name myapp --image-scanning-configuration scanOnPush=true

# Registry-wide enhanced scanning (Inspector)
aws ecr put-registry-scanning-configuration \
  --scan-type ENHANCED \
  --rules '[{"scanFrequency":"CONTINUOUS_SCAN","repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}]}]'
```

#### Python boto3
```python
import boto3

def enable_ecr_scanning():
    ecr = boto3.client('ecr')
    for page in ecr.get_paginator('describe_repositories').paginate():
        for repo in page['repositories']:
            name = repo['repositoryName']
            if not repo.get('imageScanningConfiguration', {}).get('scanOnPush'):
                ecr.put_image_scanning_configuration(
                    repositoryName=name,
                    imageScanningConfiguration={'scanOnPush': True})
                print(f"Enabled scan-on-push for {name}.")

# Usage
# enable_ecr_scanning()
```

---

### 40. Enable ECR Tag Immutability

**Issue**: ECR repositories allow mutable image tags (check H.3)
**Severity**: MEDIUM
**Compliance**: PCI-DSS 6.3.x, NIST CM-5, SI-7, ISO 27001 A.8.32

Immutable tags prevent an attacker with push access from overwriting a trusted tag (for example `latest`) with a malicious image.

#### AWS Console
1. **ECR Console** -> **Repositories** -> select the repo -> **Edit**
2. Set **Tag immutability** to **Immutable**
3. **Save**

#### AWS CLI
```bash
aws ecr put-image-tag-mutability \
  --repository-name myapp \
  --image-tag-mutability IMMUTABLE
```

#### Python boto3
```python
import boto3

def enforce_tag_immutability():
    ecr = boto3.client('ecr')
    for page in ecr.get_paginator('describe_repositories').paginate():
        for repo in page['repositories']:
            if repo.get('imageTagMutability') != 'IMMUTABLE':
                ecr.put_image_tag_mutability(
                    repositoryName=repo['repositoryName'],
                    imageTagMutability='IMMUTABLE')
                print(f"Set IMMUTABLE tags on {repo['repositoryName']}.")

# Usage
# enforce_tag_immutability()
```

---

### 41. Enforce In-Transit Encryption

**Issue**: Inter-service / external traffic is not TLS-encrypted (check H.4)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP ECS baseline, PCI-DSS 4.2.1, HIPAA 164.312(e)(1), GDPR Art.32, NIST SC-8, ISO 27001 A.8.24

Use ECS Service Connect with TLS for service-to-service traffic, and terminate external traffic with TLS at the load balancer. (EKS API endpoints are TLS by default.)

#### AWS Console
1. **ECS Console** -> service -> **Update** -> **Service Connect** -> enable **TLS** on the configuration
2. For external traffic, attach an HTTPS listener (ACM certificate) on the load balancer
3. **Update**

#### AWS CLI
```bash
# Enable TLS in the service's Service Connect configuration
aws ecs update-service \
  --cluster my-cluster --service myapp \
  --service-connect-configuration '{
    "enabled": true,
    "services": [{
      "portName": "app",
      "tls": { "issuerCertificateAuthority": { "awsPcaAuthorityArn": "arn:aws:acm-pca:REGION:ACCOUNT_ID:certificate-authority/CA_ID" } }
    }]
  }' \
  --force-new-deployment
```

#### Python boto3
```python
import boto3

def enable_service_connect_tls(cluster, service, port_name, pca_arn):
    ecs = boto3.client('ecs')
    ecs.update_service(
        cluster=cluster, service=service,
        serviceConnectConfiguration={
            'enabled': True,
            'services': [{
                'portName': port_name,
                'tls': {'issuerCertificateAuthority':
                        {'awsPcaAuthorityArn': pca_arn}}}]},
        forceNewDeployment=True)
    print(f"Service Connect TLS enabled on {service}.")

# Usage
# enable_service_connect_tls('my-cluster', 'myapp', 'app',
#   'arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/abcd')
```

---

## Quick Reference Commands

### Read-Only Audit Script

```bash
#!/bin/bash
# ecs-eks-quick-audit.sh - read-only checks that mirror common findings
REGION=${1:-us-east-1}

echo "== ECS clusters without Container Insights (A.1) =="
for c in $(aws ecs list-clusters --region "$REGION" --query 'clusterArns[]' --output text); do
  v=$(aws ecs describe-clusters --region "$REGION" --clusters "$c" --include SETTINGS \
    --query "clusters[0].settings[?name=='containerInsights'].value" --output text)
  [ "$v" = "enabled" ] || echo "  $c (insights=$v)"
done

echo "== EKS clusters with public unrestricted endpoint (D.1) =="
for k in $(aws eks list-clusters --region "$REGION" --query 'clusters[]' --output text); do
  cidrs=$(aws eks describe-cluster --region "$REGION" --name "$k" \
    --query 'cluster.resourcesVpcConfig.publicAccessCidrs' --output text)
  echo "$cidrs" | grep -q '0.0.0.0/0' && echo "  $k (public 0.0.0.0/0)"
done

echo "== ECR repos without scan-on-push (H.2) =="
aws ecr describe-repositories --region "$REGION" \
  --query 'repositories[?imageScanningConfiguration.scanOnPush==`false`].repositoryName'
```

### Python Bulk Hardening Function

```python
import boto3


def harden_ecs_cluster(cluster):
    """Apply cluster-level ECS hardening (Container Insights + exec logging)."""
    ecs = boto3.client('ecs')
    ecs.update_cluster_settings(
        cluster=cluster,
        settings=[{'name': 'containerInsights', 'value': 'enabled'}])
    ecs.update_cluster(
        cluster=cluster,
        configuration={'executeCommandConfiguration': {
            'logging': 'OVERRIDE',
            'logConfiguration': {
                'cloudWatchLogGroupName': '/ecs/exec-audit',
                'cloudWatchEncryptionEnabled': True}}})
    print(f"Cluster {cluster} hardened. Task-definition and service findings "
          f"require per-resource remediation - see sections above.")


# Usage
# harden_ecs_cluster('my-cluster')
```

---

## Additional Notes

### AWS IAM Permissions Required

Remediation requires write access across ECS, EKS, EC2, IAM, ECR, GuardDuty, and KMS:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:*",
                "eks:*",
                "ec2:CreateLaunchTemplate",
                "ec2:CreateFlowLogs",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ecr:PutImageScanningConfiguration",
                "ecr:PutImageTagMutability",
                "ecr:PutRegistryScanningConfiguration",
                "guardduty:UpdateDetector",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:CreateRole",
                "iam:PassRole",
                "kms:CreateKey"
            ],
            "Resource": "*"
        }
    ]
}
```

> The **scanner itself** only needs read-only permissions (see the README IAM policy). Apply remediation changes from a separate, tightly-controlled administrative principal.

### Validation Commands

After applying remediations, verify with:

```bash
# Re-run the ECS/EKS Security Scanner
ecs-eks-security-scanner security --compliance-only

# Spot-check specific controls
aws ecs describe-clusters --clusters my-cluster --include SETTINGS \
  --query "clusters[0].settings"
aws eks describe-cluster --name my-cluster \
  --query 'cluster.resourcesVpcConfig.{Public:endpointPublicAccess,Private:endpointPrivateAccess,CIDRs:publicAccessCidrs}'
```

### Emergency Response

For an exposed container environment:

```bash
# 1. Lock down a public EKS API endpoint to your IP only
MYIP=$(curl -s https://checkip.amazonaws.com)/32
aws eks update-cluster-config --name my-cluster \
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=$MYIP,endpointPrivateAccess=true

# 2. Disable public IPs on an exposed ECS service
aws ecs update-service --cluster my-cluster --service myapp \
  --network-configuration 'awsvpcConfiguration={subnets=[subnet-private1],securityGroups=[sg-app],assignPublicIp=DISABLED}' \
  --force-new-deployment

# 3. Rotate any secret found in plaintext env vars and move it to Secrets Manager.
# 4. Review GuardDuty findings and CloudTrail / EKS audit logs for abuse.
```

This comprehensive remediation guide provides solutions for all security vulnerabilities detected by the ECS/EKS Security Scanner. Each remediation includes multiple implementation methods to accommodate different operational preferences and automation requirements.
