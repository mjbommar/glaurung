# Agent Infrastructure Refactoring Guide

## Overview

The agent infrastructure has been refactored to provide clear separation between single-pass and iterative execution strategies, with comprehensive safety mechanisms and hyperparameter awareness.

## Architecture

### Base Components (`agents/base.py`)

1. **`ModelHyperparameters`**: Unified configuration for LLM generation
   - Temperature, top_p, top_k, max_tokens
   - Presence/frequency penalties
   - Seed for deterministic output

2. **`AnalysisResult`**: Standard result format with metrics
   - Answer with confidence score
   - Token usage and execution time
   - Termination reason for debugging
   - Tools used and evidence gathered

3. **`ExecutionState`**: Tracks execution for monitoring
   - Tool call deduplication
   - Evidence tracking
   - Loop pattern detection
   - Progress monitoring

4. **`AgentMetrics`**: Helper for extracting metrics from results

### Single-Pass Agent (`agents/single_pass.py`)

Optimized for straightforward queries that can be answered in one LLM call:

```python
from glaurung.llm.agents.single_pass import SinglePassAgent, SinglePassConfig

config = SinglePassConfig(
    optimize_context=True,      # Pre-load likely needed data
    fail_fast=False,            # Return partial results on error
    timeout_seconds=60.0,       # Maximum execution time
)

agent = SinglePassAgent(base_agent, config)
result = await agent.analyze(question, context, hyperparameters)
```

**Features:**
- Context pre-loading optimization
- Fast failure modes
- Configurable timeout
- Minimal overhead

**Use when:**
- Simple factual questions
- Speed is priority
- Single tool call expected
- Low complexity queries

### Iterative Refinement Agent (`agents/iterative_refinement.py`)

Sophisticated agent with multiple safety mechanisms:

```python
from glaurung.llm.agents.iterative_refinement import (
    IterativeRefinementAgent, 
    IterativeConfig
)

config = IterativeConfig(
    # Iteration control
    max_iterations=5,
    min_confidence=0.7,
    
    # Safety limits
    max_total_seconds=120.0,      # 2 minute timeout
    max_total_tokens=100_000,     # Token budget
    
    # Loop detection
    allow_repeated_tools=1,       # Allow 1 repeat per tool
    detect_state_loops=True,      # Detect behavioral loops
    
    # Progressive strategies
    progressive_temperature=True,  # Increase temp when stuck
    
    # Evidence requirements
    require_evidence=True,
    min_evidence_pieces=2,
)

agent = IterativeRefinementAgent(base_agent, config)
result = await agent.analyze(question, context, hyperparameters)
```

**Safety Mechanisms:**

1. **Time Budget**: Hard limit on total execution time
2. **Token Budget**: Prevent runaway token consumption  
3. **Loop Detection**:
   - Exact tool+args repetition tracking
   - Pattern detection (e.g., A→B→C→A→B→C)
   - Stuck state detection (no confidence improvement)

4. **Progress Requirements**:
   - Must show improvement or terminate
   - Evidence gathering tracked
   - Confidence progression monitored

5. **Progressive Temperature**:
   - Automatically increases when stuck
   - Encourages exploration of new approaches
   - Configurable increase factor and max

**Termination Reasons:**
- `CONFIDENCE_MET`: Target confidence achieved
- `MAX_ITERATIONS`: Iteration limit reached
- `TIMEOUT`: Time budget exhausted
- `TOKEN_LIMIT`: Token budget exhausted
- `LOOP_DETECTED`: Behavioral loop detected
- `NO_PROGRESS`: No improvement detected

### Factory Module (`agents/factory.py`)

Simplified agent creation with presets:

```python
from glaurung.llm.agents.factory import AnalysisAgentFactory

# Safe iterative with defaults
agent = AnalysisAgentFactory.create_safe_iterative_agent(
    max_time_seconds=120,
    max_tokens=100_000
)

# Fast single-pass
agent = AnalysisAgentFactory.create_fast_single_pass_agent(
    timeout=30
)

# Auto-select strategy based on question
result = await AnalysisAgentFactory.analyze_with_best_strategy(
    question,
    context,
    prefer_speed=False,
    require_high_confidence=True
)
```

## Migration Guide

### From Old `iterative.py`

**Old:**
```python
from glaurung.llm.agents.iterative import IterativeAgent

agent = IterativeAgent(base_agent, strategy)
result = await agent.run_with_refinement(question, context)
```

**New:**
```python
from glaurung.llm.agents.iterative_refinement import (
    IterativeRefinementAgent,
    IterativeConfig
)

config = IterativeConfig(
    max_iterations=strategy.max_iterations,
    min_confidence=strategy.min_confidence,
    # Add safety limits
    max_total_seconds=120.0,
    max_total_tokens=100_000,
)
agent = IterativeRefinementAgent(base_agent, config)
result = await agent.analyze(question, context)
```

### CLI Integration

Update `cli/commands/ask.py`:

```python
from glaurung.llm.agents.factory import AnalysisAgentFactory

# Add CLI argument
parser.add_argument(
    "--strategy",
    choices=["single", "iterative", "auto"],
    default="auto",
    help="Execution strategy"
)

# In _analyze_binary method
if args.strategy == "single":
    agent = AnalysisAgentFactory.create_fast_single_pass_agent(
        model=args.model
    )
elif args.strategy == "iterative":
    agent = AnalysisAgentFactory.create_safe_iterative_agent(
        model=args.model,
        max_time_seconds=args.timeout or 120
    )
else:  # auto
    # Let factory decide based on question
    result = await AnalysisAgentFactory.analyze_with_best_strategy(
        question,
        context,
        prefer_speed=args.quick,
        require_high_confidence=not args.quick
    )
```

## Configuration Examples

### High-Confidence Analysis

For malware analysis requiring thorough investigation:

```python
config = IterativeConfig(
    max_iterations=10,
    min_confidence=0.85,
    max_total_seconds=300,       # 5 minutes
    max_total_tokens=200_000,
    require_evidence=True,
    min_evidence_pieces=5,
    progressive_temperature=True,
    allow_repeated_tools=2,      # Allow more exploration
)
```

### Quick Triage

For fast initial assessment:

```python
config = SinglePassConfig(
    optimize_context=True,
    fail_fast=False,
    timeout_seconds=30,
)
```

### Balanced Approach

For general analysis with safety:

```python
config = IterativeConfig(
    max_iterations=5,
    min_confidence=0.7,
    max_total_seconds=120,
    max_total_tokens=100_000,
    detect_state_loops=True,
    progressive_temperature=True,
    allow_partial_results=True,
)
```

## Hyperparameter Control

Both agents support fine-grained hyperparameter control:

```python
from glaurung.llm.agents.base import ModelHyperparameters

# Custom generation parameters
params = ModelHyperparameters(
    temperature=0.7,        # Higher for creative tasks
    top_p=0.9,             # Nucleus sampling
    max_tokens=2048,       # Limit response length
    seed=42,               # Reproducible output
)

# Works with both agent types
result = await agent.analyze(question, context, params)
```

## Testing

Run the comprehensive test suite:

```bash
uvx pytest python/tests/test_agent_refactor.py -v
```

Key test areas:
- Hyperparameter passing
- Loop detection
- Progress tracking
- Timeout handling
- Token budgets
- Progressive temperature
- Evidence requirements

## Performance Considerations

### Single-Pass Agent
- **Latency**: ~2-10 seconds typical
- **Token Usage**: ~1-5k tokens typical
- **Best for**: Simple queries, fact lookup, quick checks

### Iterative Agent
- **Latency**: ~10-60 seconds typical
- **Token Usage**: ~5-50k tokens typical  
- **Best for**: Complex analysis, malware investigation, high-confidence needs

### Optimization Tips

1. **Pre-load context** for single-pass to reduce tool calls
2. **Set appropriate timeouts** based on query complexity
3. **Use token budgets** to control costs
4. **Enable loop detection** to prevent infinite loops
5. **Configure evidence requirements** based on domain

## Debugging

Use termination reasons and metadata to understand execution:

```python
result = await agent.analyze(question, context)

print(f"Terminated: {result.terminated_reason}")
print(f"Iterations: {result.iterations_used}")
print(f"Confidence: {result.confidence:.1%}")
print(f"Tokens used: {result.total_tokens}")
print(f"Time: {result.execution_time:.1f}s")

if result.metadata:
    print(f"Metadata: {result.metadata}")
```

## Future Enhancements

Planned improvements:
1. Graph-based workflows for multi-stage analysis
2. Streaming support for progressive results
3. Parallel tool execution optimization
4. Adaptive strategy selection based on early signals
5. Integration with pydantic-ai's native retry mechanisms