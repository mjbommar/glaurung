# LLM Integration Roadmap for Glaurung (Pydantic AI Based)

## Executive Summary

This roadmap outlines the design and implementation strategy for integrating Large Language Models (LLMs) into Glaurung's binary analysis pipeline using **Pydantic AI** as the foundation. Pydantic AI provides a production-ready agent framework with built-in support for OpenAI, Anthropic, and Google Gemini, along with powerful features like dependency injection, structured outputs, and type-safe tool integration. This approach significantly reduces boilerplate while maintaining flexibility and type safety.

## Why Pydantic AI?

Pydantic AI offers several advantages over building a custom LLM abstraction:

1. **Built by Pydantic Team**: Deep integration with Pydantic validation, used by OpenAI SDK, Anthropic SDK, and major AI frameworks
2. **Production Ready**: Type-safe dependency injection, comprehensive testing support, and Logfire integration for observability
3. **Multi-Model Support**: Native support for OpenAI, Anthropic, Gemini, and many other providers
4. **Structured Outputs**: First-class support for validated, typed responses using Pydantic models
5. **Tool System**: Elegant tool/function calling with automatic validation and retry
6. **Streaming**: Built-in streaming with partial validation
7. **Less Code**: Eliminates need for custom provider abstractions and prompt management boilerplate

## 1. Module Hierarchy (Simplified)

```
glaurung/
├── llm/
│   ├── __init__.py
│   ├── agents/              # Domain-specific agents
│   │   ├── __init__.py
│   │   ├── binary.py        # Binary analysis agent
│   │   ├── symbols.py       # Symbol analysis agent
│   │   ├── strings.py       # String/IOC analysis agent
│   │   ├── decompile.py     # Decompilation assistant
│   │   └── vulnerability.py # Vulnerability detection
│   ├── models/              # Pydantic models for outputs
│   │   ├── __init__.py
│   │   ├── analysis.py      # Analysis result models
│   │   ├── iocs.py          # IOC extraction models
│   │   └── vulnerabilities.py # Vulnerability models
│   ├── tools/               # Reusable tools for agents
│   │   ├── __init__.py
│   │   ├── disassembly.py   # Disassembly tools
│   │   ├── database.py      # Database query tools
│   │   └── search.py        # Code search tools
│   ├── dependencies.py      # Dependency injection types
│   └── config.py            # Configuration and model selection
```

## 2. Core Models and Dependencies

### 2.1 Output Models (`models/analysis.py`)

```python
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class ThreatLevel(str, Enum):
    """Threat level assessment"""
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class BinaryAnalysis(BaseModel):
    """Comprehensive binary analysis output"""
    
    summary: str = Field(..., description="High-level summary of binary purpose")
    functionality: List[str] = Field(..., description="Key functionalities identified")
    threat_level: ThreatLevel = Field(..., description="Assessed threat level")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score")
    
    # Detailed findings
    suspicious_behaviors: List[str] = Field(default_factory=list)
    security_features: Dict[str, bool] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    
    # IOC findings
    network_iocs: List["NetworkIOC"] = Field(default_factory=list)
    file_iocs: List["FileIOC"] = Field(default_factory=list)
    registry_iocs: List["RegistryIOC"] = Field(default_factory=list)

class FunctionAnalysis(BaseModel):
    """Function-level analysis output"""
    
    suggested_name: str = Field(..., description="Meaningful function name")
    purpose: str = Field(..., description="Function purpose explanation")
    parameters: List["ParameterInfo"] = Field(default_factory=list)
    return_type: Optional[str] = None
    algorithm: Optional[str] = None
    vulnerabilities: List["VulnerabilityFinding"] = Field(default_factory=list)

class ParameterInfo(BaseModel):
    """Function parameter information"""
    name: str
    type: str
    purpose: str

class VulnerabilityFinding(BaseModel):
    """Security vulnerability finding"""
    
    type: str = Field(..., description="Vulnerability type (e.g., buffer overflow)")
    severity: str = Field(..., description="CVSS severity level")
    location: str = Field(..., description="Code location")
    description: str = Field(..., description="Detailed description")
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
```

### 2.2 IOC Models (`models/iocs.py`)

```python
from pydantic import BaseModel, Field, validator
from typing import Optional
import re

class NetworkIOC(BaseModel):
    """Network-based IOC"""
    
    type: str = Field(..., description="IOC type: ip, domain, url, email")
    value: str = Field(..., description="The IOC value")
    context: Optional[str] = None
    confidence: float = Field(0.8, ge=0, le=1)
    
    @validator('value')
    def validate_format(cls, v, values):
        """Validate IOC format based on type"""
        ioc_type = values.get('type')
        if ioc_type == 'ip':
            # Validate IP format
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v):
                raise ValueError(f"Invalid IP format: {v}")
        elif ioc_type == 'domain':
            # Validate domain format
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
                raise ValueError(f"Invalid domain format: {v}")
        return v

class FileIOC(BaseModel):
    """File system IOC"""
    
    path: str
    type: str = Field(..., description="file, directory, or wildcard")
    purpose: Optional[str] = None
    suspicious: bool = False

class RegistryIOC(BaseModel):
    """Windows registry IOC"""
    
    key: str
    value_name: Optional[str] = None
    data: Optional[str] = None
    operation: str = Field(..., description="read, write, delete")
```

### 2.3 Dependencies (`dependencies.py`)

```python
from dataclasses import dataclass
from typing import Optional, Any
from pathlib import Path
import glaurung

@dataclass
class BinaryContext:
    """Context for binary analysis agents"""
    
    artifact: "glaurung.triage.TriagedArtifact"
    file_path: Path
    max_analysis_depth: int = 3
    include_disassembly: bool = False
    
    @property
    def format_str(self) -> str:
        """Get binary format as string"""
        if self.artifact.verdicts:
            return str(self.artifact.verdicts[0].format)
        return "Unknown"
    
    @property
    def architecture(self) -> str:
        """Get architecture as string"""
        if self.artifact.verdicts:
            return str(self.artifact.verdicts[0].arch)
        return "Unknown"
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get binary metadata for prompts"""
        return {
            "path": str(self.file_path),
            "size": self.artifact.size_bytes,
            "format": self.format_str,
            "arch": self.architecture,
            "entropy": self.artifact.entropy.overall if self.artifact.entropy else 0,
            "imports_count": self.artifact.symbols.imports_count if self.artifact.symbols else 0,
            "exports_count": self.artifact.symbols.exports_count if self.artifact.symbols else 0,
            "strings_count": self.artifact.strings.ascii_count if self.artifact.strings else 0,
        }

@dataclass
class AnalysisConfig:
    """Configuration for analysis agents"""
    
    model: str = "openai:gpt-4o-mini"
    temperature: float = 0.3
    max_retries: int = 3
    enable_caching: bool = True
    cache_ttl: int = 3600
    verbose: bool = False
```

## 3. Agent Implementations

### 3.1 Binary Analysis Agent (`agents/binary.py`)

```python
from pydantic_ai import Agent, RunContext
from pydantic_ai.provider import OpenAIProvider, AnthropicProvider, GoogleGeminiProvider
from typing import Union
import asyncio

from ..models.analysis import BinaryAnalysis, ThreatLevel
from ..models.iocs import NetworkIOC, FileIOC
from ..dependencies import BinaryContext, AnalysisConfig
from ..tools import get_strings, get_imports, calculate_entropy

# Create the binary analysis agent
binary_agent = Agent(
    'openai:gpt-4o-mini',
    deps_type=BinaryContext,
    output_type=BinaryAnalysis,
    system_prompt="""You are an expert binary analyst and reverse engineer.
    Analyze binaries for functionality, threats, and IOCs.
    Be thorough but concise. Focus on security-relevant findings."""
)

@binary_agent.system_prompt
async def add_binary_metadata(ctx: RunContext[BinaryContext]) -> str:
    """Add binary metadata to system prompt"""
    metadata = ctx.deps.get_metadata()
    return f"""
Binary Analysis Context:
- File: {metadata['path']}
- Format: {metadata['format']} ({metadata['arch']})
- Size: {metadata['size']:,} bytes
- Entropy: {metadata['entropy']:.2f}
- Imports: {metadata['imports_count']}
- Exports: {metadata['exports_count']}
"""

@binary_agent.tool
async def analyze_strings(ctx: RunContext[BinaryContext]) -> Dict[str, Any]:
    """Extract and analyze strings from binary"""
    strings_data = ctx.deps.artifact.strings
    if not strings_data:
        return {"error": "No strings data available"}
    
    return {
        "total_strings": strings_data.ascii_count,
        "languages": strings_data.language_counts if hasattr(strings_data, 'language_counts') else {},
        "ioc_counts": strings_data.ioc_counts if hasattr(strings_data, 'ioc_counts') else {},
        "sample_strings": strings_data.strings[:20] if strings_data.strings else []
    }

@binary_agent.tool
async def analyze_imports(ctx: RunContext[BinaryContext]) -> Dict[str, Any]:
    """Analyze imported functions"""
    symbols = ctx.deps.artifact.symbols
    if not symbols:
        return {"error": "No symbols data available"}
    
    suspicious = []
    if hasattr(symbols, 'suspicious_imports'):
        suspicious = symbols.suspicious_imports
    
    return {
        "total_imports": symbols.imports_count,
        "libraries": symbols.libs_count,
        "suspicious_count": symbols.suspicious_count if hasattr(symbols, 'suspicious_count') else 0,
        "suspicious_imports": suspicious,
        "security_flags": {
            "nx": symbols.nx if hasattr(symbols, 'nx') else None,
            "aslr": symbols.aslr if hasattr(symbols, 'aslr') else None,
            "pie": symbols.pie if hasattr(symbols, 'pie') else None,
        }
    }

@binary_agent.tool
async def check_packers(ctx: RunContext[BinaryContext]) -> Dict[str, Any]:
    """Check for packers and obfuscation"""
    entropy = ctx.deps.artifact.entropy
    if not entropy:
        return {"error": "No entropy data available"}
    
    findings = []
    if entropy.overall > 7.0:
        findings.append(f"High overall entropy: {entropy.overall:.2f}")
    
    if hasattr(entropy, 'sections'):
        for section in entropy.sections:
            if section.entropy > 7.5:
                findings.append(f"High entropy in {section.name}: {section.entropy:.2f}")
    
    return {
        "overall_entropy": entropy.overall,
        "packed_likelihood": "high" if entropy.overall > 7.0 else "low",
        "findings": findings
    }

# Convenience function for running analysis
async def analyze_binary(
    artifact: "glaurung.triage.TriagedArtifact",
    file_path: Path,
    config: Optional[AnalysisConfig] = None
) -> BinaryAnalysis:
    """Run comprehensive binary analysis"""
    
    config = config or AnalysisConfig()
    context = BinaryContext(artifact=artifact, file_path=file_path)
    
    # Select model based on config
    if config.model.startswith("anthropic"):
        model = AnthropicProvider(model=config.model.split(":")[1])
    elif config.model.startswith("google"):
        model = GoogleGeminiProvider(model=config.model.split(":")[1])
    else:
        model = config.model  # Use string format for OpenAI
    
    # Run the agent
    result = await binary_agent.run(
        "Analyze this binary comprehensively. Identify functionality, threats, and IOCs.",
        deps=context,
        model=model,
        temperature=config.temperature,
        max_retries=config.max_retries
    )
    
    return result.output
```

### 3.2 Decompilation Assistant (`agents/decompile.py`)

```python
from pydantic_ai import Agent, RunContext
from pydantic import BaseModel, Field
from typing import List, Optional

from ..models.analysis import FunctionAnalysis, ParameterInfo
from ..dependencies import BinaryContext

class DecompilationRequest(BaseModel):
    """Request for decompilation improvement"""
    raw_code: str = Field(..., description="Raw decompiled code")
    function_address: str = Field(..., description="Function address")
    calling_convention: Optional[str] = None
    cross_references: Optional[Dict[str, List[str]]] = None

decompile_agent = Agent(
    'openai:gpt-4o',  # Use more powerful model for code analysis
    output_type=FunctionAnalysis,
    system_prompt="""You are an expert reverse engineer specializing in decompilation.
    Analyze decompiled code and provide meaningful names, identify algorithms,
    and detect vulnerabilities. Focus on clarity and security."""
)

@decompile_agent.tool_plain
def identify_patterns(code: str) -> List[str]:
    """Identify common code patterns"""
    patterns = []
    
    # Check for common patterns
    if "malloc" in code or "calloc" in code:
        patterns.append("dynamic_memory_allocation")
    if "strcpy" in code or "strcat" in code:
        patterns.append("unsafe_string_operations")
    if "socket" in code or "connect" in code:
        patterns.append("network_operations")
    if "CreateFile" in code or "fopen" in code:
        patterns.append("file_operations")
    if "RegOpenKey" in code:
        patterns.append("registry_operations")
    
    # Check for crypto patterns
    crypto_constants = ["0x67452301", "0xEFCDAB89", "0x98BADCFE"]  # MD5 constants
    if any(const in code for const in crypto_constants):
        patterns.append("possible_cryptography")
    
    # Check for anti-debug
    if "IsDebuggerPresent" in code or "CheckRemoteDebuggerPresent" in code:
        patterns.append("anti_debugging")
    
    return patterns

@decompile_agent.tool_plain
def suggest_variable_names(code: str) -> Dict[str, str]:
    """Suggest meaningful variable names based on usage"""
    suggestions = {}
    
    # Common patterns
    patterns = {
        r"v\d+.*socket": "socket_fd",
        r"v\d+.*file": "file_handle",
        r"v\d+.*buffer": "data_buffer",
        r"v\d+.*len": "buffer_length",
        r"v\d+.*count": "item_count",
        r"v\d+.*index": "loop_index",
        r"v\d+.*result": "operation_result",
        r"v\d+.*error": "error_code",
        r"v\d+.*ptr": "data_pointer",
        r"v\d+.*addr": "memory_address",
    }
    
    # This is simplified - in practice would use regex
    import re
    for pattern, suggested_name in patterns.items():
        matches = re.findall(pattern, code)
        for match in matches:
            suggestions[match] = suggested_name
    
    return suggestions

async def improve_decompilation(
    request: DecompilationRequest,
    context: Optional[BinaryContext] = None
) -> FunctionAnalysis:
    """Improve decompiled code with meaningful names and analysis"""
    
    prompt = f"""
    Analyze this decompiled function:
    
    Address: {request.function_address}
    Calling Convention: {request.calling_convention or 'unknown'}
    
    Code:
    ```c
    {request.raw_code}
    ```
    
    Provide:
    1. A meaningful function name
    2. Purpose explanation
    3. Parameter analysis
    4. Any security vulnerabilities
    """
    
    if request.cross_references:
        prompt += f"\n\nCross-references:\n{request.cross_references}"
    
    result = await decompile_agent.run(prompt)
    return result.output
```

### 3.3 IOC Extraction Agent (`agents/strings.py`)

```python
from pydantic_ai import Agent, RunContext
from pydantic import BaseModel, Field
from typing import List, Dict, Any

from ..models.iocs import NetworkIOC, FileIOC, RegistryIOC

class IOCExtractionResult(BaseModel):
    """Result of IOC extraction"""
    
    network_iocs: List[NetworkIOC] = Field(default_factory=list)
    file_iocs: List[FileIOC] = Field(default_factory=list)
    registry_iocs: List[RegistryIOC] = Field(default_factory=list)
    
    suspicious_strings: List[str] = Field(default_factory=list)
    encryption_keys: List[str] = Field(default_factory=list)
    
    threat_assessment: str = Field(..., description="Overall threat assessment")
    confidence: float = Field(..., ge=0, le=1)

ioc_agent = Agent(
    'openai:gpt-4o-mini',
    output_type=IOCExtractionResult,
    system_prompt="""You are a threat intelligence analyst specializing in IOC extraction.
    Analyze strings and identify indicators of compromise.
    Be thorough in categorizing network, file, and registry IOCs.
    Consider context when assessing threat level."""
)

@ioc_agent.tool_plain
def validate_network_ioc(ioc_type: str, value: str) -> bool:
    """Validate network IOC format"""
    import re
    
    validators = {
        'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
        'ipv6': r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$',
        'domain': r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$',
        'url': r'^https?://.*',
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    }
    
    pattern = validators.get(ioc_type)
    if pattern:
        return bool(re.match(pattern, value))
    return False

@ioc_agent.tool_plain
def classify_file_path(path: str) -> Dict[str, Any]:
    """Classify file path for suspiciousness"""
    suspicious_paths = [
        '/tmp/', '/var/tmp/', '/dev/shm/',  # Linux temp
        'C:\\Windows\\Temp\\', 'C:\\Users\\Public\\',  # Windows temp
        'C:\\ProgramData\\', '%APPDATA%',  # Windows persistence
        '/etc/cron', '/etc/systemd',  # Linux persistence
        '/etc/passwd', '/etc/shadow',  # Sensitive files
    ]
    
    classification = {
        'path': path,
        'suspicious': any(s in path for s in suspicious_paths),
        'type': 'unknown'
    }
    
    if path.endswith('.exe') or path.endswith('.dll'):
        classification['type'] = 'executable'
    elif path.endswith('.bat') or path.endswith('.ps1') or path.endswith('.sh'):
        classification['type'] = 'script'
    elif path.endswith('.txt') or path.endswith('.log'):
        classification['type'] = 'data'
    
    return classification

async def extract_iocs(
    strings: List[str],
    binary_context: Optional[BinaryContext] = None
) -> IOCExtractionResult:
    """Extract and classify IOCs from strings"""
    
    # Prepare strings for analysis
    strings_text = "\n".join(strings[:1000])  # Limit to first 1000 strings
    
    prompt = f"""
    Analyze these strings extracted from a binary and identify all IOCs:
    
    Strings:
    {strings_text}
    
    Categorize all findings as:
    - Network IOCs (IPs, domains, URLs, emails)
    - File paths (especially suspicious locations)
    - Registry keys (Windows only)
    - Encryption keys or suspicious constants
    
    Assess the overall threat level based on the IOCs found.
    """
    
    if binary_context:
        prompt += f"\n\nBinary format: {binary_context.format_str}"
    
    result = await ioc_agent.run(prompt)
    return result.output
```

## 4. Tools Implementation

### 4.1 Shared Tools (`tools/__init__.py`)

```python
from pydantic_ai import FunctionTool
import glaurung
from typing import List, Dict, Any

def get_strings_tool() -> FunctionTool:
    """Create tool for string extraction"""
    
    async def extract_strings(
        file_path: str,
        min_length: int = 4,
        encoding: str = "ascii"
    ) -> List[str]:
        """Extract strings from binary file"""
        # This would call into Glaurung's string extraction
        artifact = glaurung.triage.analyze_path(file_path)
        if artifact.strings and artifact.strings.strings:
            return [s.value for s in artifact.strings.strings[:100]]
        return []
    
    return FunctionTool(extract_strings)

def get_disassembly_tool() -> FunctionTool:
    """Create tool for disassembly"""
    
    async def disassemble(
        file_path: str,
        address: int,
        length: int = 100
    ) -> str:
        """Disassemble bytes at address"""
        # This would integrate with future disassembly engine
        return f"Disassembly at {hex(address)} not yet implemented"
    
    return FunctionTool(disassemble)

def get_symbol_tool() -> FunctionTool:
    """Create tool for symbol lookup"""
    
    async def lookup_symbol(
        file_path: str,
        symbol_name: str
    ) -> Dict[str, Any]:
        """Look up symbol information"""
        artifact = glaurung.triage.analyze_path(file_path)
        if artifact.symbols:
            # Search for symbol in imports/exports
            return {
                "found": False,
                "message": "Symbol lookup not yet implemented"
            }
        return {"error": "No symbols available"}
    
    return FunctionTool(lookup_symbol)
```

## 5. Configuration and Model Selection

### 5.1 Configuration (`config.py`)

```python
from pydantic import BaseModel, Field
from pydantic_ai import Provider
from typing import Optional, Dict, Any
import os
from pathlib import Path
import yaml

class LLMConfig(BaseModel):
    """LLM configuration settings"""
    
    # Model selection
    default_model: str = Field("openai:gpt-4o-mini", description="Default model to use")
    analysis_model: str = Field("openai:gpt-4o-mini", description="Model for binary analysis")
    decompile_model: str = Field("openai:gpt-4o", description="Model for decompilation")
    
    # API keys (use environment variables)
    openai_api_key: Optional[str] = Field(None, description="OpenAI API key")
    anthropic_api_key: Optional[str] = Field(None, description="Anthropic API key")
    gemini_api_key: Optional[str] = Field(None, description="Google Gemini API key")
    
    # Performance settings
    temperature: float = Field(0.3, ge=0, le=1)
    max_retries: int = Field(3, ge=0)
    timeout: int = Field(30, description="Request timeout in seconds")
    
    # Caching
    enable_cache: bool = Field(True)
    cache_dir: Path = Field(Path.home() / ".cache" / "glaurung" / "llm")
    cache_ttl: int = Field(3600, description="Cache TTL in seconds")
    
    # Rate limiting
    max_requests_per_minute: int = Field(60)
    max_tokens_per_minute: int = Field(100000)
    
    # Observability
    enable_logfire: bool = Field(False, description="Enable Pydantic Logfire")
    logfire_token: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Load configuration from environment variables"""
        return cls(
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            default_model=os.getenv("GLAURUNG_LLM_MODEL", "openai:gpt-4o-mini"),
            enable_logfire=os.getenv("GLAURUNG_LOGFIRE", "false").lower() == "true",
            logfire_token=os.getenv("LOGFIRE_TOKEN"),
        )
    
    @classmethod
    def from_yaml(cls, path: Path) -> "LLMConfig":
        """Load configuration from YAML file"""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def get_provider(self, model_string: str):
        """Get configured provider for model string"""
        provider_name = model_string.split(":")[0]
        
        if provider_name == "openai":
            from pydantic_ai.provider import OpenAIProvider
            return OpenAIProvider(api_key=self.openai_api_key)
        elif provider_name == "anthropic":
            from pydantic_ai.provider import AnthropicProvider
            return AnthropicProvider(api_key=self.anthropic_api_key)
        elif provider_name == "google" or provider_name == "gemini":
            from pydantic_ai.provider import GoogleGeminiProvider
            return GoogleGeminiProvider(api_key=self.gemini_api_key)
        else:
            raise ValueError(f"Unknown provider: {provider_name}")

# Global configuration instance
_config: Optional[LLMConfig] = None

def get_config() -> LLMConfig:
    """Get global LLM configuration"""
    global _config
    if _config is None:
        # Try loading from file first
        config_path = Path.home() / ".glaurung" / "llm.yaml"
        if config_path.exists():
            _config = LLMConfig.from_yaml(config_path)
        else:
            _config = LLMConfig.from_env()
    return _config

def set_config(config: LLMConfig):
    """Set global LLM configuration"""
    global _config
    _config = config
```

## 6. CLI Integration

### 6.1 CLI Commands

```python
import click
import asyncio
from pathlib import Path
import glaurung
from glaurung.llm.agents import binary, decompile, strings
from glaurung.llm.config import get_config

@click.group()
def llm():
    """LLM-powered analysis commands"""
    pass

@llm.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--model', help='Model to use (e.g., openai:gpt-4o)')
@click.option('--json', is_flag=True, help='Output as JSON')
async def analyze(file_path: str, model: str, json: bool):
    """Comprehensive LLM analysis of binary"""
    
    # Triage the binary first
    artifact = glaurung.triage.analyze_path(file_path)
    
    # Run LLM analysis
    config = get_config()
    if model:
        config.analysis_model = model
    
    result = await binary.analyze_binary(
        artifact=artifact,
        file_path=Path(file_path),
        config=config
    )
    
    if json:
        click.echo(result.model_dump_json(indent=2))
    else:
        click.echo(f"Summary: {result.summary}")
        click.echo(f"Threat Level: {result.threat_level.value}")
        click.echo(f"Confidence: {result.confidence:.2%}")
        
        if result.suspicious_behaviors:
            click.echo("\nSuspicious Behaviors:")
            for behavior in result.suspicious_behaviors:
                click.echo(f"  • {behavior}")
        
        if result.recommendations:
            click.echo("\nRecommendations:")
            for rec in result.recommendations:
                click.echo(f"  • {rec}")

@llm.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--limit', default=100, help='Max strings to analyze')
async def extract_iocs(file_path: str, limit: int):
    """Extract IOCs using LLM analysis"""
    
    artifact = glaurung.triage.analyze_path(file_path)
    
    if not artifact.strings or not artifact.strings.strings:
        click.echo("No strings found in binary")
        return
    
    # Get strings for analysis
    string_values = [s.value for s in artifact.strings.strings[:limit]]
    
    result = await strings.extract_iocs(string_values)
    
    click.echo(f"Threat Assessment: {result.threat_assessment}")
    click.echo(f"Confidence: {result.confidence:.2%}")
    
    if result.network_iocs:
        click.echo(f"\nNetwork IOCs ({len(result.network_iocs)}):")
        for ioc in result.network_iocs[:10]:
            click.echo(f"  • {ioc.type}: {ioc.value}")
    
    if result.file_iocs:
        click.echo(f"\nFile IOCs ({len(result.file_iocs)}):")
        for ioc in result.file_iocs[:10]:
            click.echo(f"  • {ioc.path}")

@llm.command()
@click.option('--model', help='Test specific model')
def test_connection(model: str):
    """Test LLM provider connection"""
    
    config = get_config()
    test_model = model or config.default_model
    
    try:
        from pydantic_ai import Agent
        agent = Agent(test_model)
        result = asyncio.run(agent.run("Say 'connection successful' if you can read this"))
        click.echo(f"✅ {test_model}: {result.output}")
    except Exception as e:
        click.echo(f"❌ {test_model}: {e}", err=True)
```

## 7. Implementation Roadmap

### Phase 1: Foundation with Pydantic AI (Week 1)
- [ ] Install pydantic-ai and dependencies
- [ ] Implement core models (BinaryAnalysis, IOCs, etc.)
- [ ] Set up configuration system
- [ ] Create basic binary analysis agent
- [ ] Add CLI test commands

### Phase 2: Agent Development (Week 2)
- [ ] Implement decompilation assistant agent
- [ ] Create IOC extraction agent
- [ ] Build vulnerability detection agent
- [ ] Add symbol analysis agent
- [ ] Implement shared tools

### Phase 3: Integration (Week 3)
- [ ] Integrate with existing triage pipeline
- [ ] Add streaming support for long analyses
- [ ] Implement caching with Pydantic AI
- [ ] Add multi-agent workflows
- [ ] Create comprehensive CLI

### Phase 4: Advanced Features (Week 4)
- [ ] Add Logfire integration for observability
- [ ] Implement rate limiting
- [ ] Create prompt evaluation system
- [ ] Add batch processing support
- [ ] Build report generation

### Phase 5: Testing & Polish (Week 5)
- [ ] Write comprehensive tests
- [ ] Add integration tests with real binaries
- [ ] Performance benchmarking
- [ ] Documentation
- [ ] Example notebooks

## 8. Usage Examples

### Basic Analysis

```python
import asyncio
from pathlib import Path
import glaurung
from glaurung.llm.agents.binary import analyze_binary

async def main():
    # Analyze a binary
    artifact = glaurung.triage.analyze_path("/usr/bin/ls")
    
    # Run LLM analysis
    analysis = await analyze_binary(
        artifact=artifact,
        file_path=Path("/usr/bin/ls")
    )
    
    print(f"Summary: {analysis.summary}")
    print(f"Threat: {analysis.threat_level}")
    print(f"Behaviors: {', '.join(analysis.suspicious_behaviors)}")

asyncio.run(main())
```

### IOC Extraction with Validation

```python
from glaurung.llm.agents.strings import extract_iocs

async def find_iocs(binary_path: str):
    artifact = glaurung.triage.analyze_path(binary_path)
    
    if artifact.strings and artifact.strings.strings:
        strings = [s.value for s in artifact.strings.strings]
        result = await extract_iocs(strings)
        
        # Validated IOCs with Pydantic models
        for ioc in result.network_iocs:
            print(f"{ioc.type}: {ioc.value} (confidence: {ioc.confidence})")

asyncio.run(find_iocs("/path/to/malware"))
```

### Multi-Agent Analysis

```python
from pydantic_ai import Agent
from glaurung.llm.agents import binary_agent, decompile_agent, ioc_agent

async def comprehensive_analysis(file_path: str):
    """Run multiple agents for comprehensive analysis"""
    
    artifact = glaurung.triage.analyze_path(file_path)
    context = BinaryContext(artifact=artifact, file_path=Path(file_path))
    
    # Run agents concurrently
    results = await asyncio.gather(
        binary_agent.run("Analyze binary", deps=context),
        ioc_agent.run("Extract IOCs", deps=context),
        decompile_agent.run("Suggest improvements", deps=context)
    )
    
    return {
        "binary_analysis": results[0].output,
        "iocs": results[1].output,
        "code_analysis": results[2].output
    }
```

### Streaming Analysis

```python
async def stream_analysis(file_path: str):
    """Stream analysis results as they're generated"""
    
    artifact = glaurung.triage.analyze_path(file_path)
    context = BinaryContext(artifact=artifact, file_path=Path(file_path))
    
    async with binary_agent.stream("Analyze this binary", deps=context) as stream:
        # Process streaming response
        async for chunk in stream:
            print(chunk, end="", flush=True)
        
        # Get final validated output
        result = await stream.get_output()
        print(f"\n\nFinal threat level: {result.threat_level}")
```

## 9. Testing Strategy

### Unit Tests

```python
import pytest
from pydantic_ai.testing import TestModel
from glaurung.llm.agents.binary import binary_agent
from glaurung.llm.models.analysis import BinaryAnalysis, ThreatLevel

def test_binary_analysis():
    """Test binary analysis with mock model"""
    
    # Create test model with predetermined response
    test_model = TestModel(
        response=BinaryAnalysis(
            summary="Test binary analysis",
            functionality=["file operations", "network communication"],
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.75
        )
    )
    
    # Run agent with test model
    result = binary_agent.run_sync(
        "Analyze binary",
        model=test_model,
        deps=mock_context
    )
    
    assert result.output.threat_level == ThreatLevel.MEDIUM
    assert result.output.confidence == 0.75
    
    # Check that tools were called
    assert test_model.tool_calls[0].name == "analyze_strings"

@pytest.mark.asyncio
async def test_ioc_validation():
    """Test IOC model validation"""
    
    from glaurung.llm.models.iocs import NetworkIOC
    
    # Valid IOC
    ioc = NetworkIOC(type="ip", value="192.168.1.1")
    assert ioc.value == "192.168.1.1"
    
    # Invalid IOC should raise validation error
    with pytest.raises(ValueError):
        NetworkIOC(type="ip", value="not-an-ip")
```

### Integration Tests

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_binary_analysis(sample_elf):
    """Test with real binary sample"""
    
    artifact = glaurung.triage.analyze_path(sample_elf)
    analysis = await analyze_binary(
        artifact=artifact,
        file_path=Path(sample_elf)
    )
    
    assert analysis.summary
    assert analysis.threat_level in ThreatLevel
    assert 0 <= analysis.confidence <= 1
```

## 10. Advantages of Pydantic AI Approach

### Comparison with Custom Implementation

| Feature | Custom Implementation | Pydantic AI |
|---------|----------------------|-------------|
| **Lines of Code** | ~2000 | ~500 |
| **Provider Support** | Manual for each | Built-in for major providers |
| **Validation** | Custom validation logic | Automatic with Pydantic |
| **Streaming** | Complex async implementation | Built-in with validation |
| **Tools/Functions** | Custom tool system | Type-safe tool decorators |
| **Testing** | Mock everything | TestModel provided |
| **Observability** | Build from scratch | Logfire integration |
| **Type Safety** | Manual type hints | Full type inference |
| **Dependency Injection** | Custom context passing | Built-in DI system |
| **Retries** | Manual implementation | Automatic with backoff |

### Key Benefits

1. **Rapid Development**: Focus on domain logic, not LLM plumbing
2. **Type Safety**: Full type checking and IDE support
3. **Validation**: Automatic input/output validation
4. **Testing**: Built-in test utilities
5. **Production Ready**: Battle-tested by Pydantic team
6. **Maintainability**: Less code to maintain
7. **Flexibility**: Easy to switch providers
8. **Observability**: Free Logfire integration

## Conclusion

By leveraging Pydantic AI, we can build a robust LLM integration for Glaurung with significantly less code while gaining powerful features like type-safe tools, automatic validation, and production-ready patterns. The framework's design philosophy aligns perfectly with Glaurung's goals of being modern, type-safe, and production-ready.

The implementation focuses on domain-specific agents for binary analysis rather than building infrastructure, allowing us to deliver value quickly while maintaining flexibility for future enhancements.