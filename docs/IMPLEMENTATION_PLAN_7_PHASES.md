# OpenWatch Hybrid Scanning Implementation Plan
## 7-Phase Rollout Strategy

**Architecture**: Solution A (XCCDF Variables) + Hybrid Native Scanning Engine

**Timeline**: 6-9 months (Phases 1-4), 12-18 months (Phases 5-7)

**GitHub Repository**: https://github.com/Hanalyx/OpenWatch

---

## Phase 1: DISA STIGs & CIS Benchmarks with OSCAP (Months 1-2)

**Goal**: Establish foundation with battle-tested OSCAP compliance scanning

**Dependencies**: ComplianceAsCode content, MongoDB schema finalized

### Phase 1 Tasks (Detailed, PR-Ready)

#### 1.1 Enhanced ComplianceRule Model with XCCDF Variables

**Branch**: `feature/xccdf-variable-support`
**Estimated Time**: 3-4 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/models/mongo_models.py

class XCCDFVariable(BaseModel):
    """XCCDF variable definition for scan-time customization"""
    id: str  # e.g., "var_accounts_tmout"
    title: str
    description: Optional[str] = None
    type: str  # "string", "number", "boolean"
    default_value: str
    interactive: bool = True
    sensitive: bool = False
    constraints: Optional[Dict[str, Any]] = None
    # constraints examples:
    # - {"min_value": 60, "max_value": 3600}
    # - {"choices": ["300", "600", "900"]}
    # - {"pattern": "^grub\\.pbkdf2\\.sha512\\."}

class ComplianceRule(Document):
    """Enhanced model with XCCDF variables and scanner routing"""

    # Existing fields...
    rule_id: str
    version: str
    metadata: RuleMetadata

    # NEW: XCCDF Variables for customization
    xccdf_variables: Optional[Dict[str, XCCDFVariable]] = Field(
        default=None,
        description="XCCDF variables that can be customized at scan time"
    )

    # NEW: Scanner routing
    scanner_type: str = Field(
        default="oscap",
        description="Scanner to use: oscap, inspec, python, cloud_api, etc."
    )

    # NEW: Remediation content
    remediation: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Remediation content for ORSA plugins (Ansible, Bash, etc.)"
    )

    class Settings:
        name = "compliance_rules"
        indexes = [
            "rule_id",
            "scanner_type",
            [("profiles", pymongo.TEXT)]
        ]
```

**Tests**:
- Unit tests for XCCDFVariable validation
- Integration tests for MongoDB CRUD with new fields
- Migration script to update existing rules

**PR Checklist**:
- [ ] Model implementation with validation
- [ ] MongoDB indexes created
- [ ] Unit tests (>90% coverage)
- [ ] Integration tests
- [ ] Migration script for existing data
- [ ] API documentation updated

---

#### 1.2 Enhanced SCAP Converter with Variable Extraction

**Branch**: `feature/scap-converter-variables`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/cli/scap_to_openwatch_converter_enhanced.py

class EnhancedSCAPConverter:
    """Enhanced converter that extracts XCCDF variables and remediation"""

    def _extract_xccdf_variables(self, rule_yaml: Dict) -> Optional[Dict[str, XCCDFVariable]]:
        """
        Extract XCCDF variables from ComplianceAsCode rule.yml

        Example rule.yml:
        ---
        title: Set Account Inactivity Timeout
        rationale: "..."
        description: "Set timeout to {{{ xccdf_value('var_accounts_tmout') }}} seconds"

        Variables referenced:
        - var_accounts_tmout
        """
        variables = {}

        # Find variable references in description, rationale, fix
        for field in ['description', 'rationale', 'ocil', 'fixtext']:
            content = rule_yaml.get(field, '')
            # Match {{{ xccdf_value('var_name') }}}
            var_matches = re.findall(r'\{\{\{\s*xccdf_value\([\'"](\w+)[\'"]\)\s*\}\}\}', content)

            for var_name in var_matches:
                if var_name not in variables:
                    # Load variable definition from ComplianceAsCode
                    var_def = self._load_variable_definition(var_name)
                    variables[var_name] = XCCDFVariable(
                        id=var_name,
                        title=var_def.get('title', var_name),
                        description=var_def.get('description', ''),
                        type=var_def.get('type', 'string'),
                        default_value=str(var_def.get('default', '')),
                        interactive=True,
                        constraints=self._extract_constraints(var_def)
                    )

        return variables if variables else None

    def _extract_remediation(self, rule_yaml: Dict, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Extract remediation content (Ansible, Bash) from ComplianceAsCode

        ComplianceAsCode structure:
        - linux_os/guide/system/accounts/rule.yml (metadata)
        - linux_os/guide/system/accounts/ansible/shared.yml (Ansible tasks)
        - linux_os/guide/system/accounts/bash/shared.sh (Bash script)
        """
        remediation = {}

        rule_dir = self.content_root / rule_yaml['_source_dir']

        # Extract Ansible remediation
        ansible_file = rule_dir / 'ansible' / 'shared.yml'
        if ansible_file.exists():
            with open(ansible_file) as f:
                ansible_content = f.read()

            remediation['ansible'] = {
                'tasks': ansible_content,
                'complexity': rule_yaml.get('complexity', 'low'),
                'disruption': rule_yaml.get('disruption', 'low'),
                'variables': self._extract_ansible_variables(ansible_content)
            }

        # Extract Bash remediation
        bash_file = rule_dir / 'bash' / 'shared.sh'
        if bash_file.exists():
            with open(bash_file) as f:
                bash_content = f.read()

            remediation['bash'] = {
                'script': bash_content,
                'complexity': rule_yaml.get('complexity', 'low'),
                'disruption': rule_yaml.get('disruption', 'low'),
                'variables': self._extract_bash_variables(bash_content)
            }

        return remediation if remediation else None
```

**Tests**:
- Test variable extraction from sample rules
- Test remediation extraction (Ansible, Bash)
- Test handling of rules without variables
- Test handling of Jinja2 templates
- Integration test: full rule conversion

**PR Checklist**:
- [ ] Variable extraction logic
- [ ] Remediation extraction (Ansible, Bash)
- [ ] Unit tests for each extraction method
- [ ] Integration test with real ComplianceAsCode content
- [ ] Documentation on converter usage
- [ ] CLI help text updated

---

#### 1.3 XCCDF Data-Stream Generator

**Branch**: `feature/xccdf-generator`
**Estimated Time**: 7-10 days
**Assignee**: Backend Engineer

**Implementation**: See [MONGODB_TO_XCCDF_SCANNING.md](./MONGODB_TO_XCCDF_SCANNING.md) for complete implementation

**Key Files**:
- `backend/app/services/xccdf_generator.py` - Generate XCCDF XML from MongoDB
- `backend/app/services/xccdf_tailoring_generator.py` - Generate tailoring files
- `backend/app/services/xccdf_cache.py` - Cache generated data-streams

**Tests**:
- Generate XCCDF for sample profile (10 rules)
- Validate XCCDF against schema
- Test tailoring file generation
- Test cache invalidation
- Performance test: 500 rules → XCCDF

**PR Checklist**:
- [ ] XCCDF generator implementation
- [ ] Tailoring generator implementation
- [ ] Cache implementation
- [ ] XCCDF schema validation
- [ ] Unit tests for XML generation
- [ ] Integration test: MongoDB → XCCDF → OSCAP
- [ ] Performance benchmarks documented

---

#### 1.4 MongoDB-Based Scan Service

**Branch**: `feature/mongodb-scan-service`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/services/scan_service_mongodb.py

class MongoDBScanService:
    """Execute OSCAP scans using dynamically generated XCCDF"""

    async def execute_scan(
        self,
        host_id: str,
        profile: str,
        variable_overrides: Optional[Dict[str, str]] = None
    ) -> ScanResult:
        """
        1. Load rules from MongoDB
        2. Check cache for existing XCCDF
        3. Generate XCCDF if cache miss
        4. Generate tailoring if custom variables
        5. Execute oscap
        6. Parse results
        7. Store in MongoDB
        """
        # Implementation in MONGODB_TO_XCCDF_SCANNING.md
```

**Tests**:
- End-to-end test: MongoDB → XCCDF → OSCAP → Results
- Test with variable overrides
- Test cache hit/miss scenarios
- Test remote SSH execution
- Test error handling (invalid rules, OSCAP failures)

**PR Checklist**:
- [ ] Scan service implementation
- [ ] SSH remote execution support
- [ ] Result parsing and storage
- [ ] Error handling and logging
- [ ] Unit tests
- [ ] Integration tests with real OSCAP
- [ ] API endpoint for triggering scans

---

#### 1.5 ORSA Base Plugin Architecture

**Branch**: `feature/orsa-plugins`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/plugins/orsa/base.py

class ORSAPlugin(ABC):
    """Open Remediation Standard Adapter base class"""

    @abstractmethod
    async def execute_remediation(
        self,
        failed_rules: List[str],
        variable_overrides: Dict[str, str]
    ) -> Dict[str, bool]:
        """Execute remediation and return success status per rule"""
        pass

# File: backend/app/plugins/orsa/ansible_plugin.py
class AnsibleORSAPlugin(ORSAPlugin):
    """Extract Ansible from XCCDF and execute via ansible-playbook"""

# File: backend/app/plugins/orsa/bash_plugin.py
class BashORSAPlugin(ORSAPlugin):
    """Extract Bash from XCCDF and execute scripts"""
```

**Tests**:
- Test Ansible extraction from XCCDF
- Test Bash extraction from XCCDF
- Test variable substitution
- Test remediation execution (mocked)
- Integration test with real XCCDF

**PR Checklist**:
- [ ] ORSA base plugin class
- [ ] Ansible plugin implementation
- [ ] Bash plugin implementation
- [ ] Unit tests for each plugin
- [ ] Integration test
- [ ] Documentation on adding new plugins

---

#### 1.6 Scan Configuration API

**Branch**: `feature/scan-config-api`
**Estimated Time**: 3-4 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/routes/scan_config.py

@router.post("/api/v1/scan-configs")
async def create_scan_config(
    config: ScanConfigCreate,
    current_user: dict = Depends(get_current_user)
) -> ScanConfig:
    """
    Create custom scan configuration with variable overrides

    Request:
    {
        "name": "Production STIG - Extended Timeouts",
        "profile": "stig",
        "variable_overrides": {
            "var_accounts_tmout": "900",
            "login_banner_text": "ACME Corp Banner"
        }
    }
    """
    # Encrypt sensitive variables
    encrypted_vars = await encrypt_sensitive_variables(
        config.variable_overrides
    )

    scan_config = ScanConfiguration(
        name=config.name,
        profile=config.profile,
        variable_overrides=encrypted_vars,
        created_by=current_user["user_id"]
    )

    await scan_config.save()
    return scan_config

@router.post("/api/v1/scans")
async def execute_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
) -> ScanResult:
    """Execute scan with optional custom config"""
    service = MongoDBScanService()

    if request.scan_config_id:
        config = await ScanConfiguration.get(request.scan_config_id)
        variable_overrides = await decrypt_sensitive_variables(
            config.variable_overrides
        )
    else:
        variable_overrides = None

    return await service.execute_scan(
        host_id=request.host_id,
        profile=request.profile,
        variable_overrides=variable_overrides
    )
```

**Tests**:
- Create scan config with variables
- Execute scan with custom config
- Test sensitive variable encryption/decryption
- Test validation (invalid variables)

**PR Checklist**:
- [ ] Scan config CRUD endpoints
- [ ] Variable encryption for sensitive data
- [ ] Scan execution endpoint
- [ ] API validation and error handling
- [ ] OpenAPI documentation
- [ ] Integration tests

---

#### 1.7 Frontend: Variable Customization UI

**Branch**: `feature/variable-ui`
**Estimated Time**: 5-7 days
**Assignee**: Frontend Engineer

**Implementation**:
```typescript
// File: frontend/src/pages/ScanConfiguration/VariableCustomization.tsx

interface VariableCustomizationProps {
  profile: string;
  onSubmit: (overrides: VariableOverrides) => void;
}

const VariableCustomization: React.FC<VariableCustomizationProps> = ({
  profile,
  onSubmit
}) => {
  const { data: variables } = useProfileVariables(profile);
  const [overrides, setOverrides] = useState<VariableOverrides>({});

  return (
    <Box>
      <Typography variant="h5">Customize Compliance Variables</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Override default values for your organization's requirements
      </Typography>

      {variables?.map(variable => (
        <Box key={variable.id} sx={{ mb: 3 }}>
          {/* String variables */}
          {variable.type === 'string' && !variable.sensitive && (
            <TextField
              fullWidth
              label={variable.title}
              helperText={variable.description}
              defaultValue={variable.default_value}
              onChange={(e) => setOverrides({
                ...overrides,
                [variable.id]: e.target.value
              })}
              inputProps={{
                minLength: variable.constraints?.min_length,
                maxLength: variable.constraints?.max_length
              }}
            />
          )}

          {/* Numeric variables with choices */}
          {variable.type === 'number' && variable.constraints?.choices && (
            <FormControl fullWidth>
              <InputLabel>{variable.title}</InputLabel>
              <Select
                defaultValue={variable.default_value}
                onChange={(e) => setOverrides({
                  ...overrides,
                  [variable.id]: e.target.value
                })}
              >
                {variable.constraints.choices.map(choice => (
                  <MenuItem key={choice} value={choice}>
                    {formatChoice(choice, variable)}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>{variable.description}</FormHelperText>
            </FormControl>
          )}

          {/* Sensitive variables (masked) */}
          {variable.sensitive && (
            <TextField
              fullWidth
              label={variable.title}
              type="password"
              helperText="This value will be encrypted"
              onChange={(e) => setOverrides({
                ...overrides,
                [variable.id]: e.target.value
              })}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Lock />
                  </InputAdornment>
                )
              }}
            />
          )}
        </Box>
      ))}

      <Button
        variant="contained"
        onClick={() => onSubmit(overrides)}
        disabled={!isValid(overrides, variables)}
      >
        Save Configuration
      </Button>
    </Box>
  );
};
```

**Components**:
- Variable customization form
- Scan configuration management
- Variable validation
- Preview generated tailoring file

**Tests**:
- Component tests for each variable type
- Integration test: create config → execute scan
- Validation tests
- Accessibility tests

**PR Checklist**:
- [ ] Variable customization component
- [ ] Scan config management page
- [ ] Form validation
- [ ] Component tests
- [ ] Integration tests
- [ ] Accessibility audit

---

### Phase 1 GitHub Issues

**Epic**: "Phase 1: OSCAP Foundation with XCCDF Variables"

**Issues**:
1. **Issue #1**: Enhanced ComplianceRule Model with XCCDF Variables
2. **Issue #2**: SCAP Converter - Extract Variables and Remediation
3. **Issue #3**: XCCDF Data-Stream Generator from MongoDB
4. **Issue #4**: MongoDB-Based Scan Service
5. **Issue #5**: ORSA Plugin Architecture (Ansible, Bash)
6. **Issue #6**: Scan Configuration API Endpoints
7. **Issue #7**: Frontend Variable Customization UI

**Milestones**:
- Week 4: Backend complete, PRs merged
- Week 6: Frontend complete, PRs merged
- Week 8: End-to-end testing, documentation, Phase 1 release

---

## Phase 2: Real-Time Drift Detection (Months 3-4)

**Goal**: Continuous compliance monitoring with event-driven re-evaluation

**Dependencies**: Phase 1 complete, event streaming infrastructure

### Phase 2 Tasks (Detailed, PR-Ready)

#### 2.1 File System Monitoring Service

**Branch**: `feature/file-monitoring`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/services/continuous_monitoring/file_monitor.py

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ComplianceFileMonitor:
    """
    Monitor critical files and re-evaluate affected rules

    Example: /etc/ssh/sshd_config changes → re-check SSH rules
    """

    def __init__(self):
        self.rule_file_index = {}  # Map files → rules
        self.observers = {}  # Map hosts → Observer instances

    async def start_monitoring(self, host_id: str, profile: str):
        """
        Start monitoring files for a host

        1. Load rules for profile
        2. Extract monitored files from rules
        3. Start watchdog observers
        """
        rules = await self._load_profile_rules(profile)

        # Build file → rules index
        for rule in rules:
            monitored_files = self._extract_monitored_files(rule)
            for file_path in monitored_files:
                if file_path not in self.rule_file_index:
                    self.rule_file_index[file_path] = []
                self.rule_file_index[file_path].append(rule.rule_id)

        # Start observer
        event_handler = ComplianceFileHandler(
            rule_index=self.rule_file_index,
            host_id=host_id,
            callback=self._on_file_change
        )

        observer = Observer()
        for file_path in self.rule_file_index.keys():
            observer.schedule(event_handler, file_path, recursive=False)

        observer.start()
        self.observers[host_id] = observer

    async def _on_file_change(
        self,
        host_id: str,
        file_path: str,
        event_type: str
    ):
        """
        File changed - re-evaluate affected rules

        1. Find rules that check this file
        2. Re-run checks for those rules only
        3. Compare with previous results
        4. Alert if compliance status changed
        """
        affected_rules = self.rule_file_index.get(file_path, [])

        if not affected_rules:
            return

        logger.info(
            f"File {file_path} changed on {host_id}, "
            f"re-evaluating {len(affected_rules)} rules"
        )

        # Load previous results
        previous_results = await self._load_previous_results(
            host_id,
            affected_rules
        )

        # Re-evaluate rules
        scan_service = MongoDBScanService()
        new_results = await scan_service.execute_partial_scan(
            host_id=host_id,
            rule_ids=affected_rules
        )

        # Detect drift
        drifted_rules = self._detect_drift(previous_results, new_results)

        if drifted_rules:
            await self._alert_drift(host_id, file_path, drifted_rules)

    def _extract_monitored_files(self, rule: ComplianceRule) -> List[str]:
        """
        Extract file paths that this rule checks

        Parse OVAL checks, OCIL, remediation scripts to find files
        """
        monitored_files = set()

        # Check OVAL definitions
        if rule.checks and rule.checks.get('oval'):
            # Parse OVAL XML to find file paths
            # Example: <unix:file_test><unix:path>/etc/ssh/sshd_config</unix:path>
            monitored_files.update(self._parse_oval_files(rule.checks['oval']))

        # Check remediation scripts
        if rule.remediation:
            if rule.remediation.get('bash'):
                # Parse bash for file operations
                monitored_files.update(
                    self._parse_bash_files(rule.remediation['bash']['script'])
                )

            if rule.remediation.get('ansible'):
                # Parse Ansible for file modules
                monitored_files.update(
                    self._parse_ansible_files(rule.remediation['ansible']['tasks'])
                )

        return list(monitored_files)

class ComplianceFileHandler(FileSystemEventHandler):
    """Watchdog event handler for compliance files"""

    def __init__(self, rule_index, host_id, callback):
        self.rule_index = rule_index
        self.host_id = host_id
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            asyncio.create_task(
                self.callback(self.host_id, event.src_path, 'modified')
            )

    def on_created(self, event):
        if not event.is_directory:
            asyncio.create_task(
                self.callback(self.host_id, event.src_path, 'created')
            )

    def on_deleted(self, event):
        if not event.is_directory:
            asyncio.create_task(
                self.callback(self.host_id, event.src_path, 'deleted')
            )
```

**Tests**:
- Test file monitoring start/stop
- Test file change detection
- Test rule re-evaluation
- Test drift detection
- Test alert generation

**PR Checklist**:
- [ ] File monitor service implementation
- [ ] OVAL/Ansible/Bash file extraction
- [ ] Drift detection logic
- [ ] Unit tests
- [ ] Integration test with real file changes
- [ ] Documentation

---

#### 2.2 Cloud Event Monitoring Service

**Branch**: `feature/cloud-event-monitoring`
**Estimated Time**: 7-10 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/services/continuous_monitoring/cloud_monitor.py

class CloudEventMonitor:
    """
    Monitor cloud events (CloudTrail, Azure Activity Log, GCP Audit)

    Example: New S3 bucket created → check encryption immediately
    """

    async def monitor_aws_cloudtrail(self, account_id: str):
        """
        Stream CloudTrail events and evaluate compliance

        Events of interest:
        - CreateBucket → check S3 encryption
        - CreateUser → check IAM policies
        - ModifyVpc → check network ACLs
        - PutBucketPolicy → check public access
        """
        import boto3

        # Subscribe to CloudTrail via CloudWatch Logs
        logs_client = boto3.client('logs')

        # Stream events
        async for event in self._stream_cloudtrail(account_id, logs_client):
            await self._process_cloudtrail_event(account_id, event)

    async def _process_cloudtrail_event(
        self,
        account_id: str,
        event: Dict[str, Any]
    ):
        """
        Process CloudTrail event and run relevant checks

        Example event:
        {
            "eventName": "CreateBucket",
            "requestParameters": {
                "bucketName": "new-bucket-123"
            }
        }
        """
        event_name = event.get('eventName')

        # Map events to compliance rules
        event_rule_mapping = {
            'CreateBucket': ['aws_s3_bucket_encryption', 'aws_s3_public_access'],
            'CreateUser': ['aws_iam_user_mfa', 'aws_iam_password_policy'],
            'ModifyVpc': ['aws_vpc_flow_logs', 'aws_vpc_security_groups'],
        }

        if event_name in event_rule_mapping:
            rule_ids = event_rule_mapping[event_name]

            logger.info(
                f"CloudTrail event {event_name} detected, "
                f"checking {len(rule_ids)} rules"
            )

            # Extract resource identifier
            resource_id = self._extract_resource_id(event)

            # Run compliance checks
            scanner = CloudScannerPlugin()
            for rule_id in rule_ids:
                rule = await ComplianceRule.find_one(
                    ComplianceRule.rule_id == rule_id
                )

                result = await scanner.check(
                    rule=rule,
                    target={
                        'account_id': account_id,
                        'resource_id': resource_id,
                        'resource_type': event.get('eventSource', '').split('.')[0]
                    },
                    context={}
                )

                # Store result
                await self._store_realtime_check(account_id, rule_id, result)

                # Alert if failed
                if result.status == 'fail':
                    await self._alert_immediate_violation(
                        account_id,
                        resource_id,
                        rule_id,
                        result
                    )
```

**Tests**:
- Test CloudTrail event streaming (mocked)
- Test event-to-rule mapping
- Test compliance check execution
- Test alert generation
- Integration test with AWS (test account)

**PR Checklist**:
- [ ] AWS CloudTrail monitoring
- [ ] Event-to-rule mapping
- [ ] Real-time check execution
- [ ] Alert integration
- [ ] Unit tests
- [ ] Integration tests
- [ ] Documentation

---

#### 2.3 Kubernetes Event Monitoring

**Branch**: `feature/k8s-event-monitoring`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/services/continuous_monitoring/k8s_monitor.py

class KubernetesEventMonitor:
    """
    Monitor Kubernetes events and check new resources

    Example: New Pod created → check security context immediately
    """

    async def monitor_cluster(self, cluster_id: str):
        """Stream K8s events and evaluate compliance"""
        from kubernetes import client, watch

        v1 = client.CoreV1Api()
        w = watch.Watch()

        # Watch Pod events
        for event in w.stream(v1.list_pod_for_all_namespaces):
            await self._process_pod_event(cluster_id, event)

    async def _process_pod_event(self, cluster_id: str, event: Dict):
        """
        Process Pod event

        Events: ADDED, MODIFIED, DELETED
        Checks: security context, resource limits, image vulnerability
        """
        if event['type'] == 'ADDED':
            pod = event['object']

            # Find rules for Pod resources
            pod_rules = await ComplianceRule.find(
                {
                    'scanner_type': 'kubernetes',
                    'check_implementation.resource_type': 'Pod'
                }
            ).to_list()

            # Check Pod compliance
            scanner = ContainerScannerPlugin()
            for rule in pod_rules:
                result = await scanner.check(
                    rule=rule,
                    target={
                        'cluster_id': cluster_id,
                        'namespace': pod.metadata.namespace,
                        'pod_name': pod.metadata.name
                    },
                    context={'pod_spec': pod.to_dict()}
                )

                if result.status == 'fail':
                    await self._alert_k8s_violation(cluster_id, pod, rule, result)
```

**Tests**:
- Test K8s event streaming (mocked)
- Test Pod compliance checks
- Test alert generation
- Integration test with test cluster

**PR Checklist**:
- [ ] K8s event monitoring
- [ ] Pod security checks
- [ ] Alert integration
- [ ] Unit tests
- [ ] Integration tests
- [ ] Documentation

---

#### 2.4 Drift Detection & Alerting

**Branch**: `feature/drift-detection`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/services/drift_detection.py

class DriftDetectionService:
    """
    Detect compliance drift and generate alerts

    Drift = compliance status changed from pass → fail
    """

    async def detect_drift(
        self,
        target_id: str,
        rule_id: str,
        new_result: CheckResult
    ) -> Optional[DriftEvent]:
        """
        Compare new result with previous and detect drift
        """
        # Load previous result
        previous_result = await self._load_latest_result(target_id, rule_id)

        if not previous_result:
            # First check - no drift
            return None

        # Check for status change
        if previous_result.status == 'pass' and new_result.status == 'fail':
            # DRIFT DETECTED
            drift_event = DriftEvent(
                target_id=target_id,
                rule_id=rule_id,
                previous_status='pass',
                new_status='fail',
                detected_at=datetime.utcnow(),
                trigger_type=new_result.metadata.get('trigger'),  # 'file_change', 'cloud_event', etc.
                evidence=new_result.evidence
            )

            await drift_event.save()

            # Generate alert
            await self._generate_alert(drift_event)

            return drift_event

        return None

    async def _generate_alert(self, drift_event: DriftEvent):
        """
        Generate alert via configured channels

        Channels: Email, Slack, PagerDuty, Webhook
        """
        rule = await ComplianceRule.get(drift_event.rule_id)

        alert = Alert(
            severity='high' if rule.metadata.severity == 'high' else 'medium',
            title=f"Compliance Drift Detected: {rule.metadata.name}",
            description=f"Rule {rule.rule_id} changed from pass to fail on {drift_event.target_id}",
            metadata={
                'drift_event_id': str(drift_event.id),
                'rule_id': rule.rule_id,
                'target_id': drift_event.target_id,
                'trigger_type': drift_event.trigger_type
            }
        )

        # Send via all configured channels
        await self.alert_service.send(alert)
```

**Tests**:
- Test drift detection (pass→fail)
- Test no drift scenarios
- Test alert generation
- Test multiple alert channels

**PR Checklist**:
- [ ] Drift detection service
- [ ] Alert generation
- [ ] Multi-channel alerting (email, Slack, webhook)
- [ ] Unit tests
- [ ] Integration tests
- [ ] Documentation

---

#### 2.5 Real-Time Monitoring Dashboard

**Branch**: `feature/realtime-dashboard`
**Estimated Time**: 7-10 days
**Assignee**: Frontend Engineer

**Implementation**:
```typescript
// File: frontend/src/pages/RealTimeMonitoring/Dashboard.tsx

const RealTimeMonitoringDashboard: React.FC = () => {
  const { data: monitoredTargets } = useMonitoredTargets();
  const { data: recentDrifts } = useRecentDrifts();
  const { data: liveEvents } = useLiveEvents();  // WebSocket

  return (
    <Grid container spacing={3}>
      {/* Monitoring Status */}
      <Grid item xs={12} md={4}>
        <Card>
          <CardContent>
            <Typography variant="h6">Monitoring Status</Typography>
            <List>
              {monitoredTargets?.map(target => (
                <ListItem key={target.id}>
                  <ListItemIcon>
                    {target.status === 'active' ? (
                      <CheckCircle color="success" />
                    ) : (
                      <Error color="error" />
                    )}
                  </ListItemIcon>
                  <ListItemText
                    primary={target.name}
                    secondary={`${target.monitored_rules} rules monitored`}
                  />
                </ListItem>
              ))}
            </List>
          </CardContent>
        </Card>
      </Grid>

      {/* Recent Drift Events */}
      <Grid item xs={12} md={8}>
        <Card>
          <CardContent>
            <Typography variant="h6">Recent Drift Events</Typography>
            <Timeline>
              {recentDrifts?.map(drift => (
                <TimelineItem key={drift.id}>
                  <TimelineSeparator>
                    <TimelineDot color="error" />
                    <TimelineConnector />
                  </TimelineSeparator>
                  <TimelineContent>
                    <Typography variant="subtitle1">
                      {drift.rule_name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {drift.target_name} - {formatDistanceToNow(drift.detected_at)} ago
                    </Typography>
                    <Typography variant="caption">
                      Trigger: {drift.trigger_type}
                    </Typography>
                  </TimelineContent>
                </TimelineItem>
              ))}
            </Timeline>
          </CardContent>
        </Card>
      </Grid>

      {/* Live Event Stream */}
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6">Live Event Stream</Typography>
            <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
              {liveEvents?.map(event => (
                <Alert
                  key={event.id}
                  severity={event.severity}
                  sx={{ mb: 1 }}
                >
                  <AlertTitle>
                    {event.type}: {event.title}
                  </AlertTitle>
                  {event.description}
                </Alert>
              ))}
            </Box>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );
};
```

**Components**:
- Real-time monitoring status
- Drift event timeline
- Live event stream (WebSocket)
- Monitoring configuration

**Tests**:
- Component tests
- WebSocket integration tests
- E2E tests with Playwright

**PR Checklist**:
- [ ] Real-time dashboard UI
- [ ] WebSocket integration
- [ ] Component tests
- [ ] E2E tests
- [ ] Documentation

---

### Phase 2 GitHub Issues

**Epic**: "Phase 2: Real-Time Drift Detection"

**Issues**:
1. **Issue #8**: File System Monitoring Service
2. **Issue #9**: Cloud Event Monitoring (AWS CloudTrail)
3. **Issue #10**: Kubernetes Event Monitoring
4. **Issue #11**: Drift Detection & Alerting
5. **Issue #12**: Real-Time Monitoring Dashboard

**Milestones**:
- Week 10: File monitoring complete
- Week 12: Cloud/K8s monitoring complete
- Week 14: Dashboard complete, Phase 2 release

---

## Phase 3: Custom Organization Rules (Months 5-6)

**Goal**: Allow organizations to create custom compliance rules beyond standard content

**Dependencies**: Phase 1 complete, scanner plugin architecture

### Phase 3 Tasks (Detailed, PR-Ready)

#### 3.1 Python Script Scanner Plugin

**Branch**: `feature/python-scanner`
**Estimated Time**: 7-10 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/scanners/python_scanner.py

from RestrictedPython import compile_restricted, safe_globals
import resource

class PythonScannerPlugin(ScannerPlugin):
    """
    Execute custom Python scripts as compliance checks

    Sandboxed execution with:
    - Resource limits (CPU, memory)
    - Network restrictions
    - File system restrictions
    - Timeout enforcement
    """

    scanner_type = ScannerType.PYTHON

    async def check(
        self,
        rule: ComplianceRule,
        target: Dict[str, Any],
        context: Dict[str, Any]
    ) -> CheckResult:
        """
        Execute Python check script in sandbox

        Rule structure:
        {
            "rule_id": "custom_api_ssl_check",
            "scanner_type": "python",
            "check_implementation": {
                "script": '''
import requests

def check(target, context):
    # Check if API endpoint uses TLS 1.3
    response = requests.get(
        f"https://{target['hostname']}/api/health",
        verify=True
    )

    tls_version = response.raw.version

    return {
        "status": "pass" if tls_version >= 0x0304 else "fail",
        "message": f"TLS version: {hex(tls_version)}",
        "evidence": {
            "tls_version": hex(tls_version),
            "cipher": response.raw.cipher()
        }
    }
                ''',
                "timeout": 30,
                "required_packages": ["requests"],
                "allowed_network": ["*.example.com"],
                "allowed_files": []
            }
        }
        """
        script = rule.check_implementation.get('script', '')
        timeout = rule.check_implementation.get('timeout', 30)

        # Compile with restrictions
        byte_code = compile_restricted(script, '<inline>', 'exec')

        if byte_code.errors:
            raise ValueError(f"Script compilation failed: {byte_code.errors}")

        # Execute in sandbox
        result = await self._execute_sandboxed(
            byte_code=byte_code,
            target=target,
            context=context,
            timeout=timeout,
            allowed_packages=rule.check_implementation.get('required_packages', []),
            allowed_network=rule.check_implementation.get('allowed_network', []),
            allowed_files=rule.check_implementation.get('allowed_files', [])
        )

        return CheckResult(
            rule_id=rule.rule_id,
            status=result['status'],
            message=result['message'],
            details=result.get('evidence', {}),
            evidence=[result],
            remediation_available=bool(rule.remediation_implementation),
            scan_duration_ms=result.get('duration_ms', 0)
        )

    async def _execute_sandboxed(
        self,
        byte_code,
        target: Dict,
        context: Dict,
        timeout: int,
        allowed_packages: List[str],
        allowed_network: List[str],
        allowed_files: List[str]
    ) -> Dict:
        """
        Execute Python bytecode in restricted environment

        Security measures:
        1. RestrictedPython compiler
        2. Safe builtins (no file, exec, eval, etc.)
        3. Resource limits (CPU, memory)
        4. Network restrictions
        5. Timeout enforcement
        """
        # Set resource limits
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))  # 512MB

        # Prepare restricted globals
        restricted_globals = self._get_safe_globals(allowed_packages)
        restricted_globals.update({
            'target': target,
            'context': context,
            '__builtins__': self._get_restricted_builtins(
                allowed_network=allowed_network,
                allowed_files=allowed_files
            )
        })

        # Execute
        start_time = time.time()
        exec(byte_code, restricted_globals)
        duration_ms = (time.time() - start_time) * 1000

        # Call check function
        check_func = restricted_globals.get('check')
        if not check_func:
            raise ValueError("Script must define 'check(target, context)' function")

        result = check_func(target, context)
        result['duration_ms'] = duration_ms

        return result

    def _get_restricted_builtins(
        self,
        allowed_network: List[str],
        allowed_files: List[str]
    ) -> Dict:
        """
        Provide restricted builtins

        Allowed:
        - Basic types (int, str, list, dict, etc.)
        - Safe functions (len, range, enumerate, etc.)
        - Approved modules (requests, json, etc.)

        Blocked:
        - File operations (open, file, etc.)
        - Code execution (exec, eval, compile, etc.)
        - System access (os, sys, subprocess, etc.)
        - Unrestricted network (socket, etc.)
        """
        return {
            # Safe builtins
            'len': len,
            'range': range,
            'enumerate': enumerate,
            'zip': zip,
            'map': map,
            'filter': filter,
            'sorted': sorted,
            'sum': sum,
            'min': min,
            'max': max,

            # Safe types
            'int': int,
            'str': str,
            'float': float,
            'bool': bool,
            'list': list,
            'dict': dict,
            'tuple': tuple,
            'set': set,

            # Approved modules (with restrictions)
            'requests': self._get_restricted_requests(allowed_network),
            'json': json,
            're': re,
            'datetime': datetime,
            'math': math,
        }
```

**Tests**:
- Test safe script execution
- Test sandbox restrictions (file access blocked, network restricted)
- Test timeout enforcement
- Test resource limits
- Test malicious script detection

**PR Checklist**:
- [ ] Python scanner implementation
- [ ] RestrictedPython integration
- [ ] Resource limit enforcement
- [ ] Network/file restrictions
- [ ] Security tests (attempt to break sandbox)
- [ ] Documentation

---

#### 3.2 Custom Rule Builder API

**Branch**: `feature/custom-rule-builder`
**Estimated Time**: 7-10 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/routes/custom_rules.py

@router.post("/api/v1/custom-rules")
async def create_custom_rule(
    rule: CustomRuleCreate,
    current_user: dict = Depends(get_current_user)
) -> ComplianceRule:
    """
    Create custom organization-specific rule

    Request:
    {
        "rule_id": "acme_corp_api_tls_13",
        "metadata": {
            "name": "ACME Corp API Must Use TLS 1.3",
            "description": "Internal APIs must use TLS 1.3 or higher",
            "severity": "high",
            "category": "Network Security"
        },
        "scanner_type": "python",
        "check_implementation": {
            "script": "...",
            "timeout": 30,
            "required_packages": ["requests"]
        },
        "profiles": {
            "acme_internal": {
                "enabled": true,
                "severity": "high"
            }
        }
    }
    """
    # Validate rule
    validation_result = await validate_custom_rule(rule)
    if not validation_result.valid:
        raise HTTPException(
            status_code=400,
            detail=validation_result.errors
        )

    # Test rule execution (dry-run)
    if rule.test_target:
        test_result = await test_custom_rule(rule, rule.test_target)
        if not test_result.success:
            raise HTTPException(
                status_code=400,
                detail=f"Rule test failed: {test_result.error}"
            )

    # Create rule
    compliance_rule = ComplianceRule(
        rule_id=f"custom_{current_user['org_id']}_{rule.rule_id}",
        version="1.0",
        metadata=rule.metadata,
        scanner_type=rule.scanner_type,
        check_implementation=rule.check_implementation,
        remediation_implementation=rule.remediation_implementation,
        profiles=rule.profiles,
        custom=True,
        organization_id=current_user['org_id'],
        created_by=current_user['user_id'],
        created_at=datetime.utcnow()
    )

    await compliance_rule.save()

    return compliance_rule

async def validate_custom_rule(rule: CustomRuleCreate) -> ValidationResult:
    """
    Validate custom rule

    Checks:
    - Script syntax (Python, Bash, etc.)
    - Required fields present
    - Scanner type supported
    - Security restrictions (no dangerous operations)
    """
    errors = []

    # Validate scanner type
    if rule.scanner_type not in [e.value for e in ScannerType]:
        errors.append(f"Invalid scanner type: {rule.scanner_type}")

    # Validate Python script
    if rule.scanner_type == 'python':
        try:
            from RestrictedPython import compile_restricted
            byte_code = compile_restricted(
                rule.check_implementation['script'],
                '<inline>',
                'exec'
            )
            if byte_code.errors:
                errors.extend(byte_code.errors)
        except Exception as e:
            errors.append(f"Script compilation failed: {e}")

    # Validate remediation (if provided)
    if rule.remediation_implementation:
        # Validate remediation syntax
        pass

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors
    )

async def test_custom_rule(
    rule: CustomRuleCreate,
    test_target: Dict
) -> TestResult:
    """
    Test custom rule against sample target

    Executes rule in sandbox and returns result
    """
    try:
        scanner = get_scanner_plugin(rule.scanner_type)

        # Create temporary rule
        temp_rule = ComplianceRule(**rule.dict())

        # Execute check
        result = await scanner.check(
            rule=temp_rule,
            target=test_target,
            context={}
        )

        return TestResult(
            success=True,
            result=result
        )
    except Exception as e:
        return TestResult(
            success=False,
            error=str(e)
        )
```

**Tests**:
- Test custom rule creation
- Test validation (valid/invalid rules)
- Test rule testing (dry-run)
- Test organization isolation

**PR Checklist**:
- [ ] Custom rule API implementation
- [ ] Rule validation
- [ ] Dry-run testing
- [ ] Organization isolation
- [ ] Unit tests
- [ ] Integration tests
- [ ] API documentation

---

#### 3.3 Rule Template Library

**Branch**: `feature/rule-templates`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/services/rule_templates.py

class RuleTemplateLibrary:
    """
    Pre-built rule templates for common use cases

    Users can customize templates instead of writing from scratch
    """

    TEMPLATES = {
        'http_api_check': {
            'name': 'HTTP API Health Check',
            'description': 'Check if HTTP API endpoint is healthy',
            'scanner_type': 'python',
            'script_template': '''
import requests

def check(target, context):
    endpoint = context.get('endpoint', '/api/health')
    url = f"https://{target['hostname']}{endpoint}"

    try:
        response = requests.get(url, timeout=10, verify=True)

        return {
            "status": "pass" if response.status_code == 200 else "fail",
            "message": f"HTTP {response.status_code}",
            "evidence": {
                "status_code": response.status_code,
                "response_time_ms": response.elapsed.total_seconds() * 1000
            }
        }
    except Exception as e:
        return {
            "status": "fail",
            "message": f"Request failed: {e}",
            "evidence": {"error": str(e)}
        }
            ''',
            'parameters': [
                {
                    'name': 'endpoint',
                    'type': 'string',
                    'default': '/api/health',
                    'description': 'API endpoint path'
                }
            ]
        },

        'file_permission_check': {
            'name': 'File Permission Check',
            'description': 'Check file permissions and ownership',
            'scanner_type': 'python',
            'script_template': '''
import os
import stat

def check(target, context):
    file_path = context.get('file_path')
    expected_mode = context.get('expected_mode', '0644')
    expected_owner = context.get('expected_owner', 'root')

    if not os.path.exists(file_path):
        return {
            "status": "fail",
            "message": f"File {file_path} does not exist",
            "evidence": {"file_exists": False}
        }

    # Check permissions
    file_stat = os.stat(file_path)
    actual_mode = oct(stat.S_IMODE(file_stat.st_mode))[2:]

    # Check ownership
    import pwd
    actual_owner = pwd.getpwuid(file_stat.st_uid).pw_name

    passed = (actual_mode == expected_mode and actual_owner == expected_owner)

    return {
        "status": "pass" if passed else "fail",
        "message": f"Mode: {actual_mode} (expected {expected_mode}), Owner: {actual_owner} (expected {expected_owner})",
        "evidence": {
            "actual_mode": actual_mode,
            "expected_mode": expected_mode,
            "actual_owner": actual_owner,
            "expected_owner": expected_owner
        }
    }
            ''',
            'parameters': [
                {'name': 'file_path', 'type': 'string', 'required': True},
                {'name': 'expected_mode', 'type': 'string', 'default': '0644'},
                {'name': 'expected_owner', 'type': 'string', 'default': 'root'}
            ]
        },

        'database_query_check': {
            'name': 'Database Query Check',
            'description': 'Execute SQL query and verify result',
            'scanner_type': 'sql',
            'implementation_template': {
                'db_type': 'postgresql',
                'query': 'SELECT setting FROM pg_settings WHERE name=%(param)s',
                'assertion': {
                    'type': 'equals',
                    'column': 'setting',
                    'expected': '%(expected_value)s'
                }
            },
            'parameters': [
                {'name': 'param', 'type': 'string', 'required': True},
                {'name': 'expected_value', 'type': 'string', 'required': True}
            ]
        }
    }

    @classmethod
    def get_template(cls, template_id: str) -> Dict:
        """Get rule template by ID"""
        return cls.TEMPLATES.get(template_id)

    @classmethod
    def list_templates(cls) -> List[Dict]:
        """List all available templates"""
        return [
            {
                'id': template_id,
                'name': template['name'],
                'description': template['description'],
                'scanner_type': template['scanner_type'],
                'parameters': template.get('parameters', [])
            }
            for template_id, template in cls.TEMPLATES.items()
        ]

    @classmethod
    def instantiate_template(
        cls,
        template_id: str,
        parameters: Dict[str, Any]
    ) -> Dict:
        """
        Instantiate template with parameters

        Returns rule definition ready to create
        """
        template = cls.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        # Validate required parameters
        required_params = [
            p['name'] for p in template.get('parameters', [])
            if p.get('required', False)
        ]
        missing = set(required_params) - set(parameters.keys())
        if missing:
            raise ValueError(f"Missing required parameters: {missing}")

        # Substitute parameters
        if 'script_template' in template:
            script = template['script_template']
            # Substitute context.get('param') with actual values
            for param_name, param_value in parameters.items():
                script = script.replace(
                    f"context.get('{param_name}')",
                    f"'{param_value}'"
                )

            return {
                'scanner_type': template['scanner_type'],
                'check_implementation': {
                    'script': script,
                    'timeout': 30
                }
            }
        elif 'implementation_template' in template:
            impl = json.dumps(template['implementation_template'])
            for param_name, param_value in parameters.items():
                impl = impl.replace(f'%({param_name})s', str(param_value))

            return {
                'scanner_type': template['scanner_type'],
                'check_implementation': json.loads(impl)
            }
```

**API Endpoints**:
```python
@router.get("/api/v1/rule-templates")
async def list_rule_templates() -> List[Dict]:
    """List all available rule templates"""
    return RuleTemplateLibrary.list_templates()

@router.post("/api/v1/rule-templates/{template_id}/instantiate")
async def instantiate_template(
    template_id: str,
    parameters: Dict[str, Any]
) -> Dict:
    """Instantiate template with parameters"""
    return RuleTemplateLibrary.instantiate_template(template_id, parameters)
```

**Tests**:
- Test template listing
- Test template instantiation
- Test parameter substitution
- Test validation

**PR Checklist**:
- [ ] Template library implementation
- [ ] Template instantiation
- [ ] API endpoints
- [ ] Unit tests
- [ ] Documentation

---

#### 3.4 Custom Rule Builder UI

**Branch**: `feature/rule-builder-ui`
**Estimated Time**: 10-14 days
**Assignee**: Frontend Engineer

**Implementation**:
```typescript
// File: frontend/src/pages/CustomRules/RuleBuilder.tsx

const CustomRuleBuilder: React.FC = () => {
  const [ruleType, setRuleType] = useState<'scratch' | 'template'>('template');
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [ruleData, setRuleData] = useState<CustomRule>({});
  const [testResult, setTestResult] = useState<TestResult | null>(null);

  const { data: templates } = useRuleTemplates();

  const handleTestRule = async () => {
    const result = await testCustomRule(ruleData, testTarget);
    setTestResult(result);
  };

  const handleSaveRule = async () => {
    await createCustomRule(ruleData);
    navigate('/custom-rules');
  };

  return (
    <Box>
      <Typography variant="h4">Custom Rule Builder</Typography>

      {/* Rule Type Selection */}
      <ToggleButtonGroup
        value={ruleType}
        exclusive
        onChange={(e, val) => setRuleType(val)}
      >
        <ToggleButton value="template">
          From Template
        </ToggleButton>
        <ToggleButton value="scratch">
          From Scratch
        </ToggleButton>
      </ToggleButtonGroup>

      {ruleType === 'template' ? (
        <>
          {/* Template Selection */}
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Select Template</InputLabel>
            <Select
              value={selectedTemplate}
              onChange={(e) => setSelectedTemplate(e.target.value)}
            >
              {templates?.map(template => (
                <MenuItem key={template.id} value={template.id}>
                  <ListItemText
                    primary={template.name}
                    secondary={template.description}
                  />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Template Parameters */}
          {selectedTemplate && (
            <TemplateParameterForm
              template={templates.find(t => t.id === selectedTemplate)}
              onChange={(params) => setRuleData({...ruleData, ...params})}
            />
          )}
        </>
      ) : (
        <>
          {/* From Scratch */}
          <Grid container spacing={2} sx={{ mt: 2 }}>
            {/* Scanner Type */}
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Scanner Type</InputLabel>
                <Select
                  value={ruleData.scanner_type}
                  onChange={(e) => setRuleData({
                    ...ruleData,
                    scanner_type: e.target.value
                  })}
                >
                  <MenuItem value="python">Python Script</MenuItem>
                  <MenuItem value="bash">Bash Script</MenuItem>
                  <MenuItem value="sql">SQL Query</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* Script Editor */}
            <Grid item xs={12}>
              <CodeEditor
                language={ruleData.scanner_type === 'python' ? 'python' : 'bash'}
                value={ruleData.check_implementation?.script || ''}
                onChange={(script) => setRuleData({
                  ...ruleData,
                  check_implementation: {
                    ...ruleData.check_implementation,
                    script
                  }
                })}
              />
            </Grid>
          </Grid>
        </>
      )}

      {/* Rule Metadata */}
      <Box sx={{ mt: 3 }}>
        <Typography variant="h6">Rule Details</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Rule ID"
              value={ruleData.rule_id || ''}
              onChange={(e) => setRuleData({...ruleData, rule_id: e.target.value})}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Name"
              value={ruleData.metadata?.name || ''}
              onChange={(e) => setRuleData({
                ...ruleData,
                metadata: {...ruleData.metadata, name: e.target.value}
              })}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              multiline
              rows={3}
              label="Description"
              value={ruleData.metadata?.description || ''}
              onChange={(e) => setRuleData({
                ...ruleData,
                metadata: {...ruleData.metadata, description: e.target.value}
              })}
            />
          </Grid>
        </Grid>
      </Box>

      {/* Test Rule */}
      <Box sx={{ mt: 3 }}>
        <Typography variant="h6">Test Rule</Typography>
        <TestTargetSelector onChange={setTestTarget} />
        <Button
          variant="outlined"
          onClick={handleTestRule}
          disabled={!testTarget}
        >
          Run Test
        </Button>

        {testResult && (
          <Alert
            severity={testResult.success ? 'success' : 'error'}
            sx={{ mt: 2 }}
          >
            {testResult.success ? (
              <>
                Test passed! Result: {testResult.result.status}
                <pre>{JSON.stringify(testResult.result, null, 2)}</pre>
              </>
            ) : (
              <>Error: {testResult.error}</>
            )}
          </Alert>
        )}
      </Box>

      {/* Save Rule */}
      <Box sx={{ mt: 3 }}>
        <Button
          variant="contained"
          onClick={handleSaveRule}
          disabled={!testResult?.success}
        >
          Save Custom Rule
        </Button>
      </Box>
    </Box>
  );
};
```

**Components**:
- Template selection and parameter form
- Code editor for scripts (Monaco/CodeMirror)
- Test target selector
- Rule metadata form
- Test result display

**Tests**:
- Component tests
- Form validation tests
- Code editor integration tests
- E2E rule creation test

**PR Checklist**:
- [ ] Rule builder UI implementation
- [ ] Code editor integration
- [ ] Template parameter form
- [ ] Test functionality
- [ ] Component tests
- [ ] E2E tests
- [ ] Documentation

---

### Phase 3 GitHub Issues

**Epic**: "Phase 3: Custom Organization Rules"

**Issues**:
1. **Issue #13**: Python Script Scanner Plugin
2. **Issue #14**: Custom Rule Builder API
3. **Issue #15**: Rule Template Library
4. **Issue #16**: Custom Rule Builder UI

**Milestones**:
- Week 18: Scanner plugin complete
- Week 20: API complete
- Week 22: UI complete, Phase 3 release

---

## Phase 4: PostgreSQL SSL/Auth Settings (Months 6-7)

**Goal**: Database configuration compliance scanning

**Dependencies**: Phase 1 complete, SQL scanner plugin

### Phase 4 Tasks (Detailed, PR-Ready)

#### 4.1 SQL Scanner Plugin

**Branch**: `feature/sql-scanner`
**Estimated Time**: 7-10 days
**Assignee**: Backend Engineer

**Implementation**: See [ADVANCED_SCANNING_ARCHITECTURE.md](./ADVANCED_SCANNING_ARCHITECTURE.md) DatabaseScannerPlugin

**Key Features**:
- PostgreSQL, MySQL, MariaDB support
- Connection pooling
- Query result assertions
- Permission checks

**Tests**:
- Test PostgreSQL SSL setting check
- Test MySQL auth configuration
- Test query assertions
- Test connection error handling

**PR Checklist**:
- [ ] SQL scanner implementation (PostgreSQL, MySQL)
- [ ] Connection pooling
- [ ] Query assertion engine
- [ ] Unit tests
- [ ] Integration tests with test databases
- [ ] Documentation

---

#### 4.2 Database Compliance Rules

**Branch**: `feature/database-rules`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/data/database_rules/postgres_cis_rules.py

POSTGRES_CIS_RULES = [
    {
        "rule_id": "postgres_ssl_enabled",
        "version": "1.0",
        "metadata": {
            "name": "Ensure PostgreSQL SSL is enabled",
            "description": "PostgreSQL should require SSL connections",
            "rationale": "SSL encrypts data in transit",
            "severity": "high",
            "category": "Database Security"
        },
        "scanner_type": "sql",
        "check_implementation": {
            "db_type": "postgresql",
            "query": "SELECT setting FROM pg_settings WHERE name='ssl'",
            "assertion": {
                "type": "equals",
                "column": "setting",
                "expected": "on"
            }
        },
        "remediation_implementation": {
            "type": "manual",
            "steps": [
                "Edit postgresql.conf",
                "Set: ssl = on",
                "Restart PostgreSQL service"
            ]
        },
        "frameworks": {
            "cis": {
                "v1.0": {
                    "controls": ["2.1"]
                }
            }
        },
        "profiles": {
            "postgres_cis_level1": {"enabled": True, "severity": "high"}
        }
    },
    {
        "rule_id": "postgres_password_encryption",
        "version": "1.0",
        "metadata": {
            "name": "Ensure password encryption is enabled",
            "description": "Passwords should be encrypted in PostgreSQL",
            "severity": "high"
        },
        "scanner_type": "sql",
        "check_implementation": {
            "db_type": "postgresql",
            "query": "SELECT setting FROM pg_settings WHERE name='password_encryption'",
            "assertion": {
                "type": "equals",
                "column": "setting",
                "expected": "scram-sha-256"
            }
        }
    },
    {
        "rule_id": "postgres_log_connections",
        "version": "1.0",
        "metadata": {
            "name": "Ensure connection logging is enabled",
            "description": "Log all connection attempts for audit",
            "severity": "medium"
        },
        "scanner_type": "sql",
        "check_implementation": {
            "db_type": "postgresql",
            "query": "SELECT setting FROM pg_settings WHERE name='log_connections'",
            "assertion": {
                "type": "equals",
                "column": "setting",
                "expected": "on"
            }
        }
    },
    # ... 50+ more PostgreSQL rules
]
```

**Tests**:
- Import database rules
- Test each rule against test database
- Verify assertion logic

**PR Checklist**:
- [ ] PostgreSQL CIS rules (50+ rules)
- [ ] MySQL CIS rules (30+ rules)
- [ ] Import script
- [ ] Rule validation
- [ ] Integration tests
- [ ] Documentation

---

#### 4.3 Database Credential Management

**Branch**: `feature/database-credentials`
**Estimated Time**: 5-7 days
**Assignee**: Backend Engineer

**Implementation**:
```python
# File: backend/app/models/mongo_models.py

class DatabaseTarget(Document):
    """Database target for compliance scanning"""

    target_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    db_type: str  # postgresql, mysql, mongodb, etc.
    hostname: str
    port: int
    database: str

    # Encrypted credentials
    encrypted_credentials: str  # {username, password} encrypted

    # Connection options
    ssl_enabled: bool = True
    ssl_cert_path: Optional[str] = None
    connection_timeout: int = 30

    # Organization
    organization_id: str

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str

    class Settings:
        name = "database_targets"
        indexes = [
            "organization_id",
            "db_type"
        ]

# File: backend/app/services/database_credential_service.py

class DatabaseCredentialService:
    """Manage database credentials securely"""

    def __init__(self):
        self.encryption_key = self._load_encryption_key()
        self.cipher = Fernet(self.encryption_key)

    async def store_credentials(
        self,
        target_id: str,
        username: str,
        password: str
    ) -> None:
        """Encrypt and store database credentials"""
        credentials = json.dumps({
            "username": username,
            "password": password
        })

        encrypted = self.cipher.encrypt(credentials.encode())

        target = await DatabaseTarget.find_one(
            DatabaseTarget.target_id == target_id
        )
        target.encrypted_credentials = encrypted.decode()
        await target.save()

    async def get_credentials(
        self,
        target_id: str
    ) -> Dict[str, str]:
        """Decrypt and return credentials"""
        target = await DatabaseTarget.find_one(
            DatabaseTarget.target_id == target_id
        )

        if not target.encrypted_credentials:
            raise ValueError("No credentials stored")

        encrypted = target.encrypted_credentials.encode()
        decrypted = self.cipher.decrypt(encrypted)

        return json.loads(decrypted.decode())
```

**Tests**:
- Test credential encryption/decryption
- Test database target CRUD
- Test connection with stored credentials

**PR Checklist**:
- [ ] Database target model
- [ ] Credential encryption service
- [ ] API endpoints for target management
- [ ] Unit tests
- [ ] Integration tests
- [ ] Documentation

---

#### 4.4 Database Scanning UI

**Branch**: `feature/database-ui`
**Estimated Time**: 5-7 days
**Assignee**: Frontend Engineer

**Implementation**:
```typescript
// File: frontend/src/pages/DatabaseCompliance/DatabaseTargets.tsx

const DatabaseTargets: React.FC = () => {
  const { data: targets } = useDatabaseTargets();
  const [addDialogOpen, setAddDialogOpen] = useState(false);

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Database Targets</Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setAddDialogOpen(true)}
        >
          Add Database
        </Button>
      </Box>

      <Grid container spacing={3}>
        {targets?.map(target => (
          <Grid item xs={12} md={6} lg={4} key={target.target_id}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  <Avatar sx={{ bgcolor: 'primary.main', mr: 2 }}>
                    <Storage />
                  </Avatar>
                  <Box>
                    <Typography variant="h6">{target.name}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {target.db_type.toUpperCase()}
                    </Typography>
                  </Box>
                </Box>

                <Typography variant="body2" color="text.secondary">
                  {target.hostname}:{target.port} / {target.database}
                </Typography>

                <Box mt={2}>
                  <Chip
                    size="small"
                    label={target.ssl_enabled ? 'SSL Enabled' : 'SSL Disabled'}
                    color={target.ssl_enabled ? 'success' : 'warning'}
                  />
                </Box>
              </CardContent>

              <CardActions>
                <Button size="small" onClick={() => handleScan(target)}>
                  Scan
                </Button>
                <Button size="small" onClick={() => handleEdit(target)}>
                  Edit
                </Button>
                <Button size="small" color="error" onClick={() => handleDelete(target)}>
                  Delete
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      <AddDatabaseDialog
        open={addDialogOpen}
        onClose={() => setAddDialogOpen(false)}
        onSubmit={handleAddDatabase}
      />
    </Box>
  );
};
```

**Components**:
- Database target list
- Add/edit database form
- Credential input (masked)
- Scan execution
- Results display

**Tests**:
- Component tests
- Form validation tests
- E2E test: add database → scan

**PR Checklist**:
- [ ] Database targets UI
- [ ] Add/edit forms
- [ ] Scan execution
- [ ] Component tests
- [ ] E2E tests
- [ ] Documentation

---

### Phase 4 GitHub Issues

**Epic**: "Phase 4: Database Configuration Scanning"

**Issues**:
1. **Issue #17**: SQL Scanner Plugin
2. **Issue #18**: Database Compliance Rules (PostgreSQL, MySQL)
3. **Issue #19**: Database Credential Management
4. **Issue #20**: Database Scanning UI

**Milestones**:
- Week 24: Scanner plugin complete
- Week 26: Rules and credential management complete
- Week 28: UI complete, Phase 4 release

---

## Phase 5: Kubernetes CIS Benchmark (Months 8-12) - Long-Term Plan

**Goal**: Kubernetes cluster compliance scanning

### High-Level Components

1. **K8s Scanner Plugin** (4-6 weeks)
   - Kubernetes API client integration
   - kube-bench integration
   - OPA/Gatekeeper policy evaluation
   - Resource compliance checks (Pods, Services, NetworkPolicies, etc.)

2. **CIS Kubernetes Benchmark Rules** (3-4 weeks)
   - Import CIS Kubernetes rules
   - Map to kube-bench tests
   - Control plane checks
   - Node configuration checks
   - Pod security standards

3. **Cluster Management** (3-4 weeks)
   - Cluster registration (kubeconfig)
   - Multi-cluster support
   - Namespace filtering
   - RBAC integration

4. **K8s Remediation** (4-6 weeks)
   - kubectl apply remediations
   - YAML manifest generation
   - Helm chart updates
   - GitOps integration (ArgoCD, Flux)

5. **K8s Compliance Dashboard** (4-6 weeks)
   - Cluster compliance overview
   - Resource compliance drill-down
   - Pod security policy violations
   - Network policy gaps
   - RBAC analysis

### Milestones
- Month 8: K8s scanner plugin complete
- Month 9: CIS rules imported
- Month 10: Cluster management complete
- Month 11: Remediation complete
- Month 12: Dashboard complete, Phase 5 release

---

## Phase 6: Container Vulnerability Scanning (Months 10-14) - Long-Term Plan

**Goal**: Container image and runtime vulnerability scanning

### High-Level Components

1. **Trivy Integration** (3-4 weeks)
   - Image scanning (registry and local)
   - Filesystem scanning
   - SBOM generation
   - License compliance

2. **Container Registry Integration** (4-6 weeks)
   - Docker Hub
   - Amazon ECR
   - Azure ACR
   - Google GCR
   - Harbor, Quay

3. **Falco Runtime Security** (4-6 weeks)
   - Falco agent deployment
   - Runtime rule evaluation
   - Anomaly detection
   - Alert integration

4. **CVE Management** (3-4 weeks)
   - CVE database
   - Vulnerability tracking
   - Remediation tracking
   - SLA management

5. **Container Compliance Dashboard** (4-6 weeks)
   - Image vulnerability overview
   - Runtime security events
   - CVE trending
   - Remediation status

### Milestones
- Month 10: Trivy integration complete
- Month 11: Registry integration complete
- Month 12: Falco integration complete
- Month 13: CVE management complete
- Month 14: Dashboard complete, Phase 6 release

---

## Phase 7: AWS S3/IAM/VPC Compliance (Months 12-18) - Long-Term Plan

**Goal**: Cloud infrastructure compliance (AWS, Azure, GCP)

### High-Level Components

1. **Cloud API Scanner Plugin** (6-8 weeks)
   - AWS Boto3 integration
   - Azure SDK integration
   - GCP API integration
   - Multi-account/subscription support
   - Service-specific scanners (S3, IAM, VPC, RDS, Lambda, etc.)

2. **AWS CIS Foundations Benchmark** (4-6 weeks)
   - Import CIS AWS rules
   - IAM compliance checks
   - S3 bucket security
   - VPC network security
   - CloudTrail logging
   - Config and monitoring

3. **Cloud Asset Inventory** (4-6 weeks)
   - Automatic resource discovery
   - Asset relationships
   - Resource tagging
   - Cost tracking integration

4. **Cloud Remediation** (6-8 weeks)
   - AWS API-based remediation
   - Terraform plan generation
   - CloudFormation updates
   - Azure ARM templates
   - GCP Deployment Manager

5. **Multi-Cloud Dashboard** (6-8 weeks)
   - Cloud account overview
   - Resource compliance heat map
   - Security posture score
   - Cost optimization recommendations
   - Drift detection

### Milestones
- Month 12: Cloud scanner plugin complete
- Month 13: AWS CIS rules complete
- Month 14: Asset inventory complete
- Month 15: Remediation complete
- Month 16-17: Dashboard development
- Month 18: Phase 7 release

---

## GitHub Project Structure

Since there are currently no open projects, I recommend creating the following GitHub Projects:

### Project 1: "OpenWatch Hybrid Scanning - Foundation (Phases 1-2)"
**Timeline**: Months 1-4
**Issues**: #1-#12

**Columns**:
- Backlog
- In Progress
- In Review
- Done

### Project 2: "OpenWatch Custom Rules & Database Scanning (Phases 3-4)"
**Timeline**: Months 5-7
**Issues**: #13-#20

### Project 3: "OpenWatch Cloud-Native Compliance (Phases 5-7)"
**Timeline**: Months 8-18
**Issues**: TBD (create when Phase 4 complete)

---

## Summary

This 7-phase plan provides:

✅ **Phase 1-4**: Detailed, PR-ready tasks with:
- Branch names
- Estimated time
- Code implementations
- Test requirements
- PR checklists

✅ **Phase 5-7**: High-level roadmap with:
- Component breakdown
- Time estimates
- Milestone targets

✅ **GitHub Integration**: Ready to map to GitHub Projects and Issues

✅ **Hybrid Strategy**: Combines OSCAP (battle-tested) with modern scanning (cloud, containers, custom)

**Next Steps**:
1. Create GitHub Projects (3 projects for 7 phases)
2. Create GitHub Issues from this plan (#1-#20 for Phases 1-4)
3. Start with Phase 1, Issue #1: Enhanced ComplianceRule Model
4. Follow PR-by-PR implementation with tests and reviews

---
*Last updated: 2025-10-14*
