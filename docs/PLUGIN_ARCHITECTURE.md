# OpenWatch Plugin Architecture - Platform Integration Guide

## How OpenWatch Supports Multiple Remediation Platforms

OpenWatch doesn't directly integrate with Ansible, Chef, or Puppet. Instead, it provides a **standard interface (ORSA)** that ANY remediation system can implement. This is the key to supporting multiple platforms without platform-specific code in OpenWatch core.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         OpenWatch Core                              │
│  ┌─────────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │ Compliance      │  │ Plugin         │  │ Execution       │   │
│  │ Scanner         │  │ Registry       │  │ Engine          │   │
│  │                 │  │                │  │                 │   │
│  │ • SCAP Scanning │  │ • Import/Valid │  │ • Sandboxing    │   │
│  │ • Rule Engine   │  │ • Storage      │  │ • Monitoring    │   │
│  │ • Reporting     │  │ • Lifecycle    │  │ • Results       │   │
│  └────────┬────────┘  └────────┬───────┘  └────────┬──────────┘   │
│           │                     │                    │              │
│           └─────────────────────┴────────────────────┘              │
│                                 │                                    │
│                    ┌────────────┴────────────┐                     │
│                    │   Plugin Interface      │                     │
│                    │   (Standard API)        │                     │
│                    └────────────┬────────────┘                     │
└─────────────────────────────────┼──────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │      ORSA Standard        │
                    │ (Open Remediation Adapter)│
                    └─────────────┬─────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────┴────────┐      ┌────────┴────────┐      ┌────────┴────────┐
│ AEGIS Adapter  │      │ Ansible Adapter │      │  Chef Adapter   │
├────────────────┤      ├─────────────────┤      ├─────────────────┤
│ Implements:    │      │ Implements:     │      │ Implements:     │
│ • ORSA Interface│      │ • ORSA Interface│      │ • ORSA Interface│
│ • get_rules()  │      │ • get_rules()   │      │ • get_rules()   │
│ • submit_job() │      │ • submit_job()  │      │ • submit_job()  │
│ • get_status() │      │ • get_status()  │      │ • get_status()  │
├────────────────┤      ├─────────────────┤      ├─────────────────┤
│ Translates to: │      │ Translates to:  │      │ Translates to:  │
│ AEGIS API calls│      │ ansible-playbook│      │ knife commands  │
└────────┬───────┘      └────────┬────────┘      └────────┬────────┘
         │                       │                         │
┌────────┴───────┐      ┌────────┴────────┐      ┌────────┴────────┐
│  AEGIS System  │      │ Ansible Engine  │      │  Chef Server    │
│                │      │                 │      │                 │
│ 2000+ Rules    │      │ Playbooks       │      │ Cookbooks       │
│ Multi-Framework│      │ Roles           │      │ Recipes         │
│ API-Based      │      │ SSH-Based       │      │ Client-Based    │
└────────────────┘      └─────────────────┘      └─────────────────┘
```

## 🔌 How Each Platform Integrates

### 1. AEGIS Integration (API-Based)
```python
class AegisRemediationSystem(RemediationSystemInterface):
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        # Translates to AEGIS API call
        response = await self.http_client.post(
            "/api/v1/remediation/jobs",
            json={"host_id": job.target_host_id, "rules": job.rules}
        )
        return response["job_id"]
```

### 2. Ansible Integration (Command-Based)
```python
class AnsibleRemediationSystem(RemediationSystemInterface):
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        # Translates to ansible-playbook command
        cmd = [
            "ansible-playbook",
            "ssh_hardening.yml",
            "-i", f"{job.target_host_id},",
            "--check" if job.dry_run else ""
        ]
        process = await asyncio.create_subprocess_exec(*cmd)
        return f"ansible-job-{uuid.uuid4()}"
```

### 3. Chef Integration (API or Command-Based)
```python
class ChefRemediationSystem(RemediationSystemInterface):
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        # Translates to knife command or Chef API
        cmd = [
            "knife", "ssh",
            f"name:{job.target_host_id}",
            "sudo chef-client -o security_baseline::ssh"
        ]
        # OR: Chef Server API call
        return await self.execute_chef_run(job)
```

### 4. Puppet Integration (Bolt-Based)
```python
class PuppetRemediationSystem(RemediationSystemInterface):
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        # Translates to Puppet Bolt command
        cmd = [
            "bolt", "apply",
            "--execute", "include security::ssh",
            "--targets", job.target_host_id
        ]
        return await self.execute_bolt_plan(cmd)
```

### 5. Custom Scripts (Direct Execution)
```python
class CustomScriptRemediationSystem(RemediationSystemInterface):
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        # Direct script execution with OpenWatch context
        env = {
            "OPENWATCH_HOST_ID": job.target_host_id,
            "OPENWATCH_CONTEXT": json.dumps(job.openwatch_context)
        }
        return await self.execute_script(script_path, env)
```

## 🎯 Key Concepts

### 1. **Semantic Rule Names**
OpenWatch uses semantic names that are platform-agnostic:
- OpenWatch: `"ow-ssh-disable-root"`
- AEGIS might map to: `"RHEL-08-010550"`
- Ansible might map to: `"security_baseline::ssh::disable_root"`
- Chef might map to: `"security_baseline::ssh recipe"`

### 2. **Standard Job Format**
All platforms receive the same job request:
```python
RemediationJob(
    target_host_id="host-123",
    platform="rhel8",
    rules=["ow-ssh-disable-root"],
    dry_run=True,
    openwatch_context={...}
)
```

### 3. **Unified Results**
All platforms return results in the same format:
```python
RemediationJobResult(
    status="success",
    changes_made=True,
    validation_passed=True,
    rule_results=[...]
)
```

## 📋 Platform Capabilities Comparison

| Feature | AEGIS | Ansible | Chef | Puppet | Custom |
|---------|-------|---------|------|--------|--------|
| **Integration Type** | API | Command/API | Command/API | Command/API | Direct |
| **Execution Model** | Centralized | SSH-Based | Client-Based | Agent/Agentless | Local |
| **Rule Format** | YAML Rules | Playbooks | Cookbooks | Manifests | Scripts |
| **Dry Run Support** | ✅ | ✅ (--check) | ✅ (why-run) | ✅ (--noop) | Optional |
| **Rollback Support** | ✅ | Manual | Manual | Manual | Manual |
| **Framework Mapping** | ✅ Native | Via Tags | Via Attributes | Via Facts | Custom |
| **Parallel Execution** | ✅ | ✅ | ✅ | ✅ | Limited |

## 🔄 Workflow Example: Multi-Platform Remediation

```python
# 1. OpenWatch detects compliance failure
scan_result = await openwatch.scan_host("web-server-01", "stig")
failed_rules = scan_result.get_failed_rules()  # ["ow-ssh-disable-root"]

# 2. Query available remediation options
remediations = {}
for platform_name, adapter in registered_adapters.items():
    rules = await adapter.get_rules_for_openwatch_rule("ow-ssh-disable-root", "rhel8")
    if rules:
        remediations[platform_name] = rules

# 3. Admin chooses remediation platform based on policy
# Example policy: Use AEGIS for STIG, Ansible for custom
if scan_result.framework == "stig" and "aegis" in remediations:
    chosen_platform = "aegis"
else:
    chosen_platform = "ansible"

# 4. Execute remediation through chosen platform
job = RemediationJob(
    target_host_id="web-server-01",
    rules=["ow-ssh-disable-root"],
    platform="rhel8"
)
job_id = await adapters[chosen_platform].submit_remediation_job(job)

# 5. Monitor execution (same interface regardless of platform)
result = await adapters[chosen_platform].get_job_status(job_id)

# 6. Verify with OpenWatch
verification_scan = await openwatch.scan_host("web-server-01", "stig", rules=["ow-ssh-disable-root"])
```

## 🏗️ Creating Your Own Adapter

To integrate a new remediation system:

1. **Implement the ORSA Interface**:
```python
class MyRemediationSystem(RemediationSystemInterface):
    async def get_system_info(self) -> RemediationSystemInfo:
        return RemediationSystemInfo(
            system_id="my-remediation-system",
            name="My Custom System",
            capabilities=[...],
            supported_platforms=[...]
        )
    
    async def get_available_rules(self, **kwargs) -> List[RemediationRule]:
        # Return your system's remediation rules
    
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        # Execute remediation using your system's method
    
    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        # Check execution status
```

2. **Register with OpenWatch**:
```python
my_system = MyRemediationSystem()
adapter = OpenWatchRemediationSystemAdapter(my_system)
plugin = await adapter.register_as_openwatch_plugin()
```

3. **Map OpenWatch Rules** to your system's implementation:
```python
# In your get_available_rules() method
return [
    RemediationRule(
        semantic_name="ow-ssh-disable-root",  # Maps to OpenWatch rule
        implementations={
            "rhel": {"my_method": "disable_ssh_root"}  # Your implementation
        }
    )
]
```

## 📊 Benefits of This Architecture

1. **No Vendor Lock-in**: Organizations can use their existing tools
2. **Platform Agnostic**: OpenWatch doesn't need to know about Ansible/Chef/Puppet internals
3. **Extensible**: New platforms can be added without changing OpenWatch
4. **Flexible**: Mix and match platforms based on requirements
5. **Standard Interface**: All platforms work the same way from OpenWatch's perspective

## 🚀 Real-World Usage Patterns

### Enterprise Environment
- **AEGIS** for STIG/NIST compliance (comprehensive, certified)
- **Ansible** for custom security baselines
- **Chef** for application configuration compliance
- **Custom Scripts** for legacy system remediation

### Cloud-Native Environment
- **Terraform** adapter for infrastructure compliance
- **Kubernetes** adapter for container security policies
- **Cloud provider** adapters (AWS SSM, Azure Policy, GCP Config)

### Small Organization
- **Ansible** for everything (simple, agentless)
- **Custom Scripts** for specific needs

The beauty of the ORSA standard is that OpenWatch doesn't care which remediation system you use - it just needs the adapter to implement the standard interface. This makes OpenWatch truly platform-agnostic while enabling rich remediation capabilities through the ecosystem.