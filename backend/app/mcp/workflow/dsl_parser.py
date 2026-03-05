"""
Skill Workflow DSL Parser

Parses YAML-based skill definitions that define security automation workflows.
Supports:
- Step sequencing and parallel execution
- Conditional branching
- Input/output parameter mapping
- Error handling policies
- Approval gates
"""

import re
import yaml
import logging
from typing import Any, Dict, List, Optional, Set, Union
from enum import Enum
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class StepType(str, Enum):
    """Types of workflow steps"""
    TOOL = "tool"           # Execute a tool
    CONDITION = "condition" # Conditional branching
    PARALLEL = "parallel"   # Parallel execution group
    APPROVAL = "approval"   # Human approval gate
    LOOP = "loop"           # Loop over items
    WAIT = "wait"           # Wait for condition/time
    NOTIFY = "notify"       # Send notification
    TRANSFORM = "transform" # Transform data


class ErrorPolicy(str, Enum):
    """Error handling policies"""
    STOP = "stop"           # Stop workflow on error
    CONTINUE = "continue"   # Continue despite error
    RETRY = "retry"         # Retry the step
    FALLBACK = "fallback"   # Execute fallback step


class ApprovalLevel(str, Enum):
    """Approval requirement levels"""
    NONE = "none"
    SINGLE = "single"       # Single approver
    DUAL = "dual"           # Two approvers required
    MANAGER = "manager"     # Manager approval required


# ============================================================================
# Data Models
# ============================================================================

class StepInput(BaseModel):
    """Step input parameter definition"""
    name: str
    type: str = "string"
    description: str = ""
    required: bool = True
    default: Optional[Any] = None
    source: Optional[str] = None  # Reference to previous step output: "step_id.output_name"


class StepOutput(BaseModel):
    """Step output definition"""
    name: str
    type: str = "any"
    description: str = ""


class RetryConfig(BaseModel):
    """Retry configuration for steps"""
    max_attempts: int = 3
    delay_seconds: int = 5
    backoff_multiplier: float = 2.0
    max_delay_seconds: int = 60


class StepCondition(BaseModel):
    """Condition for conditional steps"""
    expression: str  # e.g., "${step1.output.severity} >= 'high'"
    true_branch: Optional[str] = None  # Step ID to execute if true
    false_branch: Optional[str] = None  # Step ID to execute if false


class LoopConfig(BaseModel):
    """Loop configuration"""
    items: str  # Reference to iterable: "${step1.output.hosts}"
    item_var: str = "item"  # Variable name for current item
    parallel: bool = False  # Execute iterations in parallel
    max_parallel: int = 5


class WaitConfig(BaseModel):
    """Wait step configuration"""
    duration_seconds: Optional[int] = None
    until_condition: Optional[str] = None  # Expression to evaluate
    poll_interval_seconds: int = 10
    timeout_seconds: int = 3600


class NotifyConfig(BaseModel):
    """Notification configuration"""
    channel: str  # "email", "slack", "webhook"
    recipients: List[str] = Field(default_factory=list)
    template: str = ""
    severity: str = "info"


class StepDefinition(BaseModel):
    """Complete step definition"""
    id: str
    name: str
    type: StepType = StepType.TOOL
    description: str = ""
    
    # Tool execution
    tool: Optional[str] = None  # Tool name to execute
    tool_params: Dict[str, Any] = Field(default_factory=dict)
    
    # Input/Output
    inputs: List[StepInput] = Field(default_factory=list)
    outputs: List[StepOutput] = Field(default_factory=list)
    
    # Control flow
    depends_on: List[str] = Field(default_factory=list)
    condition: Optional[StepCondition] = None
    loop: Optional[LoopConfig] = None
    
    # Parallel steps (for type=parallel)
    parallel_steps: List[str] = Field(default_factory=list)
    
    # Wait config (for type=wait)
    wait: Optional[WaitConfig] = None
    
    # Notification (for type=notify)
    notify: Optional[NotifyConfig] = None
    
    # Error handling
    error_policy: ErrorPolicy = ErrorPolicy.STOP
    retry: Optional[RetryConfig] = None
    fallback_step: Optional[str] = None
    
    # Approval
    approval_level: ApprovalLevel = ApprovalLevel.NONE
    approval_timeout_minutes: int = 60
    
    # Timeout
    timeout_seconds: int = 300

    @validator('id')
    def validate_id(cls, v):
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_-]*$', v):
            raise ValueError(f"Invalid step ID: {v}")
        return v


class SkillMetadata(BaseModel):
    """Skill metadata"""
    name: str
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    tags: List[str] = Field(default_factory=list)
    category: str = "general"
    risk_level: str = "low"
    requires_approval: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SkillInput(BaseModel):
    """Skill-level input parameter"""
    name: str
    type: str = "string"
    description: str = ""
    required: bool = True
    default: Optional[Any] = None
    validation: Optional[str] = None  # Regex or validation expression


class SkillOutput(BaseModel):
    """Skill-level output"""
    name: str
    type: str = "any"
    description: str = ""
    source: str  # Reference to step output: "step_id.output_name"


class SkillDefinition(BaseModel):
    """
    Complete Skill workflow definition.
    
    A Skill is a reusable security workflow that can be triggered
    manually or automatically in response to events.
    """
    metadata: SkillMetadata
    inputs: List[SkillInput] = Field(default_factory=list)
    outputs: List[SkillOutput] = Field(default_factory=list)
    steps: List[StepDefinition] = Field(default_factory=list)
    
    # Error handling at workflow level
    on_error: ErrorPolicy = ErrorPolicy.STOP
    on_timeout: ErrorPolicy = ErrorPolicy.STOP
    
    # Notifications
    on_start_notify: Optional[NotifyConfig] = None
    on_complete_notify: Optional[NotifyConfig] = None
    on_error_notify: Optional[NotifyConfig] = None

    def get_step(self, step_id: str) -> Optional[StepDefinition]:
        """Get step by ID"""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def get_entry_steps(self) -> List[StepDefinition]:
        """Get steps with no dependencies (entry points)"""
        return [s for s in self.steps if not s.depends_on]

    def get_dependent_steps(self, step_id: str) -> List[StepDefinition]:
        """Get steps that depend on the given step"""
        return [s for s in self.steps if step_id in s.depends_on]

    def validate_dag(self) -> List[str]:
        """Validate that steps form a valid DAG (no cycles)"""
        errors = []
        
        # Check for missing dependencies
        step_ids = {s.id for s in self.steps}
        for step in self.steps:
            for dep in step.depends_on:
                if dep not in step_ids:
                    errors.append(f"Step '{step.id}' depends on unknown step '{dep}'")
        
        # Check for cycles using DFS
        visited = set()
        rec_stack = set()
        
        def has_cycle(step_id: str) -> bool:
            visited.add(step_id)
            rec_stack.add(step_id)
            
            step = self.get_step(step_id)
            if step:
                for dep_step in self.get_dependent_steps(step_id):
                    if dep_step.id not in visited:
                        if has_cycle(dep_step.id):
                            return True
                    elif dep_step.id in rec_stack:
                        return True
            
            rec_stack.remove(step_id)
            return False
        
        for step in self.steps:
            if step.id not in visited:
                if has_cycle(step.id):
                    errors.append(f"Cycle detected involving step '{step.id}'")
        
        return errors


# ============================================================================
# Parser Implementation
# ============================================================================

class SkillParser:
    """
    Parser for Skill YAML definitions.
    
    Example YAML:
    ```yaml
    metadata:
      name: vulnerability-scan
      version: "1.0.0"
      description: Automated vulnerability scanning workflow
      category: vulnerability
      risk_level: medium
    
    inputs:
      - name: target
        type: string
        description: Target IP or hostname
        required: true
    
    steps:
      - id: port_scan
        name: Port Scan
        type: tool
        tool: nmap_scan
        tool_params:
          target: "${inputs.target}"
          ports: "1-1000"
    
      - id: vuln_scan
        name: Vulnerability Scan
        type: tool
        tool: nessus_scan
        depends_on: [port_scan]
        tool_params:
          targets: "${port_scan.output.hosts}"
          template: basic_network
    
      - id: report
        name: Generate Report
        type: tool
        tool: generate_report
        depends_on: [vuln_scan]
        tool_params:
          report_type: vulnerability
          data: "${vuln_scan.output}"
    
    outputs:
      - name: report_path
        source: report.output.file_path
    ```
    """

    def __init__(self):
        self._custom_validators: Dict[str, callable] = {}

    def register_validator(self, name: str, validator: callable) -> None:
        """Register a custom input validator"""
        self._custom_validators[name] = validator

    def parse_file(self, file_path: Union[str, Path]) -> SkillDefinition:
        """Parse a skill definition from a YAML file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Skill file not found: {file_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return self.parse_string(content)

    def parse_string(self, yaml_content: str) -> SkillDefinition:
        """Parse a skill definition from a YAML string"""
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML syntax: {e}")
        
        return self.parse_dict(data)

    def parse_dict(self, data: Dict[str, Any]) -> SkillDefinition:
        """Parse a skill definition from a dictionary"""
        if not isinstance(data, dict):
            raise ValueError("Skill definition must be a dictionary")
        
        # Parse metadata
        metadata = self._parse_metadata(data.get('metadata', {}))
        
        # Parse inputs
        inputs = self._parse_inputs(data.get('inputs', []))
        
        # Parse steps
        steps = self._parse_steps(data.get('steps', []))
        
        # Parse outputs
        outputs = self._parse_outputs(data.get('outputs', []))
        
        # Parse error handling
        on_error = ErrorPolicy(data.get('on_error', 'stop'))
        on_timeout = ErrorPolicy(data.get('on_timeout', 'stop'))
        
        # Parse notifications
        on_start_notify = self._parse_notify(data.get('on_start_notify'))
        on_complete_notify = self._parse_notify(data.get('on_complete_notify'))
        on_error_notify = self._parse_notify(data.get('on_error_notify'))
        
        skill = SkillDefinition(
            metadata=metadata,
            inputs=inputs,
            outputs=outputs,
            steps=steps,
            on_error=on_error,
            on_timeout=on_timeout,
            on_start_notify=on_start_notify,
            on_complete_notify=on_complete_notify,
            on_error_notify=on_error_notify,
        )
        
        # Validate
        errors = skill.validate_dag()
        if errors:
            raise ValueError(f"Invalid skill definition: {', '.join(errors)}")
        
        return skill

    def _parse_metadata(self, data: Dict[str, Any]) -> SkillMetadata:
        """Parse skill metadata"""
        if not data.get('name'):
            raise ValueError("Skill metadata must include 'name'")
        
        return SkillMetadata(
            name=data['name'],
            version=data.get('version', '1.0.0'),
            description=data.get('description', ''),
            author=data.get('author', ''),
            tags=data.get('tags', []),
            category=data.get('category', 'general'),
            risk_level=data.get('risk_level', 'low'),
            requires_approval=data.get('requires_approval', False),
        )

    def _parse_inputs(self, data: List[Dict[str, Any]]) -> List[SkillInput]:
        """Parse skill inputs"""
        inputs = []
        for item in data:
            if not item.get('name'):
                raise ValueError("Input must have a 'name'")
            inputs.append(SkillInput(
                name=item['name'],
                type=item.get('type', 'string'),
                description=item.get('description', ''),
                required=item.get('required', True),
                default=item.get('default'),
                validation=item.get('validation'),
            ))
        return inputs

    def _parse_outputs(self, data: List[Dict[str, Any]]) -> List[SkillOutput]:
        """Parse skill outputs"""
        outputs = []
        for item in data:
            if not item.get('name'):
                raise ValueError("Output must have a 'name'")
            if not item.get('source'):
                raise ValueError("Output must have a 'source'")
            outputs.append(SkillOutput(
                name=item['name'],
                type=item.get('type', 'any'),
                description=item.get('description', ''),
                source=item['source'],
            ))
        return outputs

    def _parse_steps(self, data: List[Dict[str, Any]]) -> List[StepDefinition]:
        """Parse workflow steps"""
        steps = []
        for item in data:
            step = self._parse_step(item)
            steps.append(step)
        return steps

    def _parse_step(self, data: Dict[str, Any]) -> StepDefinition:
        """Parse a single step"""
        if not data.get('id'):
            raise ValueError("Step must have an 'id'")
        if not data.get('name'):
            data['name'] = data['id']
        
        step_type = StepType(data.get('type', 'tool'))
        
        # Parse inputs
        inputs = []
        for inp in data.get('inputs', []):
            inputs.append(StepInput(**inp))
        
        # Parse outputs
        outputs = []
        for out in data.get('outputs', []):
            outputs.append(StepOutput(**out))
        
        # Parse condition
        condition = None
        if 'condition' in data:
            condition = StepCondition(**data['condition'])
        
        # Parse loop
        loop = None
        if 'loop' in data:
            loop = LoopConfig(**data['loop'])
        
        # Parse wait
        wait = None
        if 'wait' in data:
            wait = WaitConfig(**data['wait'])
        
        # Parse notify
        notify = None
        if 'notify' in data:
            notify = NotifyConfig(**data['notify'])
        
        # Parse retry
        retry = None
        if 'retry' in data:
            retry = RetryConfig(**data['retry'])
        
        return StepDefinition(
            id=data['id'],
            name=data['name'],
            type=step_type,
            description=data.get('description', ''),
            tool=data.get('tool'),
            tool_params=data.get('tool_params', {}),
            inputs=inputs,
            outputs=outputs,
            depends_on=data.get('depends_on', []),
            condition=condition,
            loop=loop,
            parallel_steps=data.get('parallel_steps', []),
            wait=wait,
            notify=notify,
            error_policy=ErrorPolicy(data.get('error_policy', 'stop')),
            retry=retry,
            fallback_step=data.get('fallback_step'),
            approval_level=ApprovalLevel(data.get('approval_level', 'none')),
            approval_timeout_minutes=data.get('approval_timeout_minutes', 60),
            timeout_seconds=data.get('timeout_seconds', 300),
        )

    def _parse_notify(self, data: Optional[Dict[str, Any]]) -> Optional[NotifyConfig]:
        """Parse notification config"""
        if not data:
            return None
        return NotifyConfig(
            channel=data.get('channel', 'email'),
            recipients=data.get('recipients', []),
            template=data.get('template', ''),
            severity=data.get('severity', 'info'),
        )

    def validate_inputs(
        self,
        skill: SkillDefinition,
        inputs: Dict[str, Any]
    ) -> List[str]:
        """Validate input values against skill definition"""
        errors = []
        
        for inp_def in skill.inputs:
            value = inputs.get(inp_def.name)
            
            # Check required
            if inp_def.required and value is None and inp_def.default is None:
                errors.append(f"Required input '{inp_def.name}' is missing")
                continue
            
            # Use default if not provided
            if value is None:
                continue
            
            # Type validation (basic)
            if inp_def.type == "string" and not isinstance(value, str):
                errors.append(f"Input '{inp_def.name}' must be a string")
            elif inp_def.type == "number" and not isinstance(value, (int, float)):
                errors.append(f"Input '{inp_def.name}' must be a number")
            elif inp_def.type == "boolean" and not isinstance(value, bool):
                errors.append(f"Input '{inp_def.name}' must be a boolean")
            elif inp_def.type == "array" and not isinstance(value, list):
                errors.append(f"Input '{inp_def.name}' must be an array")
            elif inp_def.type == "object" and not isinstance(value, dict):
                errors.append(f"Input '{inp_def.name}' must be an object")
            
            # Custom validation
            if inp_def.validation:
                if inp_def.validation in self._custom_validators:
                    validator = self._custom_validators[inp_def.validation]
                    if not validator(value):
                        errors.append(f"Input '{inp_def.name}' failed validation '{inp_def.validation}'")
                elif inp_def.validation.startswith('/') and inp_def.validation.endswith('/'):
                    # Regex validation
                    pattern = inp_def.validation[1:-1]
                    if not re.match(pattern, str(value)):
                        errors.append(f"Input '{inp_def.name}' does not match pattern")
        
        return errors


# ============================================================================
# Built-in Skill Templates
# ============================================================================

VULNERABILITY_SCAN_SKILL = """
metadata:
  name: vulnerability-scan
  version: "1.0.0"
  description: Automated vulnerability scanning workflow
  category: vulnerability
  risk_level: medium
  requires_approval: true

inputs:
  - name: target
    type: string
    description: Target IP address or hostname
    required: true
  - name: scan_depth
    type: string
    description: Scan depth level
    required: false
    default: standard

steps:
  - id: port_scan
    name: Port Discovery
    type: tool
    tool: nmap_scan
    tool_params:
      target: "${inputs.target}"
      ports: "1-10000"
      service_detection: true

  - id: vuln_scan
    name: Vulnerability Assessment
    type: tool
    tool: nessus_scan
    depends_on: [port_scan]
    approval_level: single
    tool_params:
      targets: "${inputs.target}"
      template: "${inputs.scan_depth == 'deep' ? 'advanced_scan' : 'basic_network'}"

  - id: cve_enrichment
    name: CVE Enrichment
    type: loop
    depends_on: [vuln_scan]
    loop:
      items: "${vuln_scan.output.vulnerabilities}"
      item_var: vuln
      parallel: true
      max_parallel: 5
    tool: cve_lookup
    tool_params:
      cve_id: "${vuln.cve_id}"

  - id: report
    name: Generate Report
    type: tool
    tool: generate_report
    depends_on: [cve_enrichment]
    tool_params:
      report_type: vulnerability
      data:
        target: "${inputs.target}"
        port_scan: "${port_scan.output}"
        vulnerabilities: "${vuln_scan.output}"
        cve_details: "${cve_enrichment.output}"
      format: pdf

outputs:
  - name: report_path
    source: report.output.file_path
  - name: vulnerability_count
    source: vuln_scan.output.total_count
  - name: critical_count
    source: vuln_scan.output.critical_count
"""

THREAT_HUNTING_SKILL = """
metadata:
  name: threat-hunting
  version: "1.0.0"
  description: Automated threat hunting workflow
  category: threat_intel
  risk_level: low

inputs:
  - name: indicator
    type: string
    description: IOC to investigate (IP, domain, hash)
    required: true
  - name: indicator_type
    type: string
    description: Type of indicator
    required: true

steps:
  - id: vt_lookup
    name: VirusTotal Lookup
    type: tool
    tool: virustotal_lookup
    tool_params:
      indicator: "${inputs.indicator}"
      indicator_type: "${inputs.indicator_type}"

  - id: misp_lookup
    name: MISP Query
    type: tool
    tool: misp_query
    tool_params:
      value: "${inputs.indicator}"
      include_correlations: true

  - id: threatbook_lookup
    name: ThreatBook Query
    type: tool
    tool: threatbook_query
    tool_params:
      indicator: "${inputs.indicator}"
      indicator_type: "${inputs.indicator_type}"
    error_policy: continue

  - id: aggregate
    name: Aggregate Results
    type: transform
    depends_on: [vt_lookup, misp_lookup, threatbook_lookup]
    tool_params:
      operation: merge
      sources:
        - "${vt_lookup.output}"
        - "${misp_lookup.output}"
        - "${threatbook_lookup.output}"

  - id: mitre_map
    name: MITRE ATT&CK Mapping
    type: tool
    tool: mitre_mapping
    depends_on: [aggregate]
    tool_params:
      indicators:
        - "${aggregate.output}"
      include_mitigations: true

outputs:
  - name: threat_score
    source: aggregate.output.combined_score
  - name: mitre_techniques
    source: mitre_map.output.techniques
  - name: full_report
    source: aggregate.output
"""

INCIDENT_RESPONSE_SKILL = """
metadata:
  name: incident-response
  version: "1.0.0"
  description: Automated incident response workflow
  category: forensics
  risk_level: high
  requires_approval: true

inputs:
  - name: alert_id
    type: string
    description: Alert ID to investigate
    required: true
  - name: auto_contain
    type: boolean
    description: Automatically contain threats
    required: false
    default: false

steps:
  - id: gather_context
    name: Gather Alert Context
    type: tool
    tool: elk_query
    tool_params:
      query: "alert.id:${inputs.alert_id}"
      index: "alerts-*"
      time_range: now-24h

  - id: analyze_chain
    name: Attack Chain Analysis
    type: tool
    tool: attack_chain_analyze
    depends_on: [gather_context]
    tool_params:
      events: "${gather_context.output.hits}"
      time_window: "24h"

  - id: check_severity
    name: Check Severity
    type: condition
    depends_on: [analyze_chain]
    condition:
      expression: "${analyze_chain.output.severity} >= 'high'"
      true_branch: containment
      false_branch: report_only

  - id: containment
    name: Threat Containment
    type: tool
    tool: firewall_block
    depends_on: [check_severity]
    approval_level: dual
    tool_params:
      ip_address: "${analyze_chain.output.attacker_ip}"
      duration: 24
      reason: "Automated containment for alert ${inputs.alert_id}"
      direction: both

  - id: report_only
    name: Generate Report Only
    type: tool
    tool: generate_report
    depends_on: [check_severity]
    tool_params:
      report_type: incident
      data: "${analyze_chain.output}"
      format: pdf

outputs:
  - name: incident_severity
    source: analyze_chain.output.severity
  - name: contained
    source: containment.output.success
"""


def get_builtin_skills() -> Dict[str, str]:
    """Get all built-in skill templates"""
    return {
        "vulnerability-scan": VULNERABILITY_SCAN_SKILL,
        "threat-hunting": THREAT_HUNTING_SKILL,
        "incident-response": INCIDENT_RESPONSE_SKILL,
    }
