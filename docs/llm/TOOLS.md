# Pydantic-AI Tool System in Glaurung

## Overview

The tool system in pydantic-ai allows LLM agents to call Python functions during their execution. This enables agents to:
- Fetch real-time data
- Perform calculations
- Interact with external systems
- Execute analysis operations

## Key Concepts

### 1. Tool Registration

Tools are Python functions registered with an agent that the LLM can call:

```python
from pydantic_ai import Agent, RunContext

agent = Agent(model="openai:gpt-4.1-mini")

# Register a tool using decorator
@agent.tool
def calculate_hash(ctx: RunContext, file_path: str, algorithm: str = "sha256") -> str:
    """Calculate file hash."""
    # Implementation here
    return hash_value

# Or register explicitly
agent.tool(my_function, name="custom_name")
```

### 2. RunContext

Every tool receives a `RunContext` as its first parameter:

```python
def my_tool(ctx: RunContext[DepsType], arg1: str, arg2: int) -> str:
    # Access dependencies
    deps = ctx.deps
    
    # Access retry count
    retries = ctx.retry
    
    # Access tool call ID
    tool_id = ctx.tool_call_id
    
    return result
```

### 3. Tool Schema

Pydantic-ai automatically generates tool schemas from:
- Function signatures
- Type hints
- Docstrings (Google/NumPy/Sphinx style)

```python
def analyze_binary(
    ctx: RunContext[AnalysisContext],
    analysis_type: Literal["static", "dynamic"],  # Enum constraint
    depth: int = 10,  # Default value
) -> Dict[str, Any]:
    """Analyze a binary file.
    
    Args:
        ctx: Runtime context
        analysis_type: Type of analysis to perform
        depth: Analysis depth level
        
    Returns:
        Analysis results dictionary
    """
    # The LLM sees the schema with types and descriptions
```

### 4. Async vs Sync Tools

```python
# Synchronous tool - for simple operations
def sync_tool(ctx: RunContext, param: str) -> str:
    return f"Processed: {param}"

# Asynchronous tool - for I/O or expensive operations  
async def async_tool(ctx: RunContext, param: str) -> str:
    await asyncio.sleep(0.1)  # Simulate I/O
    return f"Async processed: {param}"
```

**Performance Note**: When multiple tools are called, pydantic-ai runs them concurrently:
- Async functions run on the event loop
- Sync functions are offloaded to threads
- Use async unless doing blocking I/O or CPU-bound work

### 5. Tool Preparation (Dynamic Availability)

Control tool availability per run using `prepare` functions:

```python
from pydantic_ai.tools import ToolDefinition, ToolPrepareFunc

def prepare_tool(
    ctx: RunContext[DepsType], 
    tool_def: ToolDefinition
) -> Optional[ToolDefinition]:
    """Decide if tool should be available."""
    if ctx.deps.allow_dangerous:
        return tool_def  # Include tool
    else:
        return None  # Exclude tool

agent.tool(dangerous_function, prepare=prepare_tool)
```

### 6. Toolsets

Organize related tools into reusable toolsets:

```python
from pydantic_ai.tools import ToolSet

class FileAnalysisToolSet(ToolSet):
    """Tools for file analysis."""
    
    async def get_metadata(self, ctx: RunContext, path: str) -> Dict:
        """Get file metadata."""
        # Implementation
        
    async def extract_strings(self, ctx: RunContext, path: str) -> List[str]:
        """Extract strings from file."""
        # Implementation

# Register toolset with agent
agent.register_toolset(FileAnalysisToolSet())
```

### 7. Deferred Tools (Approval Required)

For operations requiring human approval:

```python
from pydantic_ai.tools import DeferredToolRequests, DeferredToolResults

# Mark tool as deferred
agent.tool(delete_file, defer=True)

# First run - returns DeferredToolRequests
result = agent.run("Delete malicious file")

if isinstance(result.output, DeferredToolRequests):
    # Get user approval
    approvals = {}
    for tool_call in result.output.approvals:
        user_approves = input(f"Approve {tool_call.tool_name}?")
        approvals[tool_call.tool_call_id] = ToolApproved() if user_approves else ToolDenied()
    
    # Continue with approvals
    final = agent.run(
        result.messages,
        deferred_tool_results=DeferredToolResults(approvals=approvals)
    )
```

## Glaurung Implementation

### AnalysisContext

Standard context for binary analysis tools:

```python
@dataclass
class AnalysisContext:
    file_path: str              # Path to binary
    artifact: TriagedArtifact   # Analysis results
    session_id: str             # Session identifier
    allow_expensive_ops: bool   # Permission flag
```

### Core Tool Categories

#### 1. Metadata Tools
- `get_file_hash`: Calculate file hashes
- `get_file_info`: Extract file metadata
- `get_entropy`: Calculate entropy

#### 2. String Analysis
- `extract_strings`: Extract strings with encoding options
- `find_patterns`: Search for patterns
- `extract_iocs`: Extract indicators of compromise

#### 3. Symbol Analysis
- `check_import`: Check for specific imports
- `get_exports`: List exported functions
- `get_libraries`: List linked libraries

#### 4. Disassembly Tools (Expensive)
- `disassemble_at_address`: Disassemble at VA
- `analyze_control_flow`: Analyze CFG
- `find_functions`: Locate functions

#### 5. Security Tools
- `check_signatures`: Check against signatures
- `run_yara`: Execute YARA rules
- `validate_iocs`: Validate detected IOCs

### Usage Examples

#### Basic Analysis Agent

```python
from glaurung.llm.tools import create_binary_analysis_agent_with_tools

# Create agent
agent = create_binary_analysis_agent_with_tools(
    model="gpt-4",
    allow_expensive=True
)

# Create context from triage
context = AnalysisContext(
    file_path="/path/to/binary",
    artifact=triaged_artifact,
    session_id="analysis_001",
    allow_expensive_ops=True
)

# Run analysis
result = agent.run_sync(
    "Analyze this binary for malicious behavior",
    deps=context
)

print(f"Analysis: {result.output}")
print(f"Tools used: {len(result.tool_calls)}")
```

#### Custom Tool Registration

```python
from pydantic_ai import Agent, RunContext

agent = Agent(model="gpt-4", deps_type=AnalysisContext)

@agent.tool
def custom_analysis(
    ctx: RunContext[AnalysisContext],
    technique: str
) -> Dict[str, Any]:
    """Perform custom analysis technique."""
    artifact = ctx.deps.artifact
    
    # Custom analysis logic
    if technique == "packing":
        return {
            "packed": artifact.entropy.overall > 7.0,
            "entropy": artifact.entropy.overall
        }
    
    return {"error": "Unknown technique"}
```

#### Using Toolsets

```python
from glaurung.llm.tools import StringAnalysisToolSet, SymbolAnalysisToolSet

agent = Agent(model="gpt-4", deps_type=AnalysisContext)

# Register toolsets
agent.register_toolset(StringAnalysisToolSet())
agent.register_toolset(SymbolAnalysisToolSet())

# Tools are now available to the agent
result = agent.run_sync(
    "Extract all URLs and check for suspicious imports",
    deps=context  
)
```

## Best Practices

### 1. Tool Design

- **Single Responsibility**: Each tool should do one thing well
- **Clear Naming**: Use descriptive names that indicate function
- **Type Safety**: Use type hints and Pydantic models
- **Error Handling**: Return errors gracefully, don't raise exceptions
- **Documentation**: Include docstrings with parameter descriptions

### 2. Performance

- Use `async` for I/O operations
- Use `sync` for CPU-bound operations  
- Limit expensive operations with preparation functions
- Cache results when appropriate
- Set reasonable timeouts

### 3. Security

- Validate all inputs
- Use deferred tools for dangerous operations
- Check permissions in context
- Limit data exposure
- Audit tool usage

### 4. Testing

```python
import pytest
from unittest.mock import Mock
from pydantic_ai import RunContext

def test_tool():
    # Create mock context
    context = AnalysisContext(
        file_path="/test",
        artifact=Mock(),
        session_id="test"
    )
    
    ctx = RunContext(deps=context, retry=0)
    
    # Test tool directly
    result = my_tool(ctx, "param")
    assert result == expected
```

## Common Patterns

### Pattern 1: Conditional Tools

```python
def prepare_based_on_format(ctx: RunContext, tool_def: ToolDefinition):
    """Only available for PE files."""
    if ctx.deps.artifact.verdicts[0].format == "PE":
        return tool_def
    return None
```

### Pattern 2: Batch Operations

```python
async def batch_analysis(
    ctx: RunContext,
    operations: List[str]
) -> List[Dict]:
    """Perform multiple operations concurrently."""
    tasks = [analyze_one(ctx, op) for op in operations]
    return await asyncio.gather(*tasks)
```

### Pattern 3: Progressive Analysis

```python
@agent.tool
def quick_check(ctx: RunContext) -> bool:
    """Quick malware check."""
    return ctx.deps.artifact.entropy.overall > 7.5

@agent.tool(prepare=lambda ctx, td: td if ctx.deps.allow_expensive_ops else None)
def deep_analysis(ctx: RunContext) -> Dict:
    """Deep analysis (expensive)."""
    # Only available when explicitly allowed
```

## Troubleshooting

### Issue: Tool Not Being Called

- Check tool is registered: `agent.tool(func)`
- Verify function signature is correct
- Ensure docstring describes purpose clearly
- Check prepare function isn't excluding it

### Issue: Schema Validation Errors

- Use proper type hints
- Ensure all parameters except `ctx` have types
- Use Pydantic models for complex types
- Add field descriptions in docstrings

### Issue: Performance Problems

- Use async for I/O operations
- Implement timeouts
- Cache expensive computations
- Use preparation functions to limit availability

## Further Reading

- [Pydantic-AI Tools Documentation](https://ai.pydantic.dev/tools/)
- [Toolsets Documentation](https://ai.pydantic.dev/toolsets/)
- [Deferred Tools Guide](https://ai.pydantic.dev/tools/#deferred-tools)
- [MCP Integration](https://ai.pydantic.dev/mcp/)