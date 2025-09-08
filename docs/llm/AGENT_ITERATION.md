# Agent Iteration Architecture Analysis

## Current State

Our agents currently operate in a **single-pass mode**:
```
User Question → Agent Planning → Tool Execution → Response
```

This works well for simple queries but fails when:
- Initial information gathering is insufficient
- Agent needs to refine understanding based on results
- Complex questions require multiple investigation paths
- Validation reveals the need for additional context

## The Problem

Current limitations:
1. **No refinement loop**: Agent can't reconsider its approach based on tool results
2. **No validation feedback**: Can't retry with better parameters when tools fail
3. **No iterative exploration**: Can't progressively narrow down investigation
4. **Single context**: Can't build understanding across multiple related queries

## Pydantic-AI Solutions

### 1. Built-in Retry Mechanisms

Pydantic-AI provides several retry patterns:

#### Tool-Level Retries
```python
@agent.tool(retries=3)
async def search_symbols(ctx: RunContext[MemoryContext], query: str) -> SymbolsSearchResult:
    result = await perform_search(query)
    if not result.matches:
        raise ModelRetry(f"No symbols found for '{query}'. Try broader search terms.")
    return result
```

#### Output Validation Retries
```python
class ValidatedAnalysis(BaseModel):
    confidence: float = Field(ge=0.7, le=1.0)
    
    @model_validator(mode='after')
    def validate_confidence(self):
        if self.confidence < 0.7:
            raise ModelRetry("Confidence too low. Please gather more evidence.")
        return self
```

### 2. Agent Iteration Control

Use `agent.iter()` for fine-grained control:

```python
async def iterative_analysis(agent, question, context):
    max_iterations = 5
    
    async with agent.iter(question, deps=context) as run:
        iterations = 0
        async for node in run:
            iterations += 1
            
            # Check if we have enough information
            if context.kb.confidence_score() > 0.8:
                break
                
            # Prevent infinite loops
            if iterations >= max_iterations:
                break
                
            # Can inject custom logic between iterations
            if isinstance(node, ToolCallNode):
                print(f"Calling tool: {node.tool_name}")
    
    return run.result
```

### 3. Graph-Based Workflows

For complex iterative refinement, use pydantic-graph:

```python
from pydantic_graph import Graph, BaseNode, End, GraphRunContext
from dataclasses import dataclass

@dataclass
class AnalysisState:
    question: str
    evidence: list[str]
    confidence: float
    iteration: int

class GatherEvidence(BaseNode[AnalysisState]):
    async def run(self, ctx: GraphRunContext[AnalysisState]) -> 'EvaluateEvidence':
        # Use tools to gather more evidence
        new_evidence = await gather_more_info(ctx.state.question)
        ctx.state.evidence.extend(new_evidence)
        ctx.state.iteration += 1
        return EvaluateEvidence()

class EvaluateEvidence(BaseNode[AnalysisState, None, str]):
    async def run(self, ctx: GraphRunContext[AnalysisState]) -> GatherEvidence | End[str]:
        # Evaluate if we have enough evidence
        ctx.state.confidence = calculate_confidence(ctx.state.evidence)
        
        if ctx.state.confidence > 0.85 or ctx.state.iteration >= 5:
            answer = synthesize_answer(ctx.state.evidence)
            return End(answer)
        else:
            # Need more evidence - loop back
            return GatherEvidence()

# Create and run the graph
graph = Graph(nodes=[GatherEvidence, EvaluateEvidence])
```

## Recommended Implementation

### Phase 1: Add Retry Mechanisms (Quick Win)

Enhance existing tools with retry logic:

```python
# In memory_agent.py
async def search_symbols(
    ctx: RunContext[MemoryContext],
    query: str,
    **kwargs
) -> SymbolsSearchResult:
    tool = build_search_symbols()
    result = tool.run(ctx.deps, ctx.deps.kb, tool.input_model(query=query, **kwargs))
    
    # Add validation and retry
    if not result.matches and ctx.retry < 2:
        suggestions = suggest_alternative_queries(query)
        raise ModelRetry(f"No matches. Try: {', '.join(suggestions)}")
    
    return result
```

### Phase 2: Implement Iterative Agent Wrapper

Create a wrapper for iterative refinement:

```python
class IterativeAgent:
    def __init__(self, base_agent, max_iterations=5):
        self.agent = base_agent
        self.max_iterations = max_iterations
    
    async def run_with_refinement(self, question, context):
        iteration = 0
        confidence_threshold = 0.8
        
        while iteration < self.max_iterations:
            # Run agent iteration
            result = await self.agent.run(
                self._build_prompt(question, iteration, context),
                deps=context
            )
            
            # Evaluate result quality
            confidence = self._evaluate_confidence(result, context)
            
            if confidence >= confidence_threshold:
                return result
            
            # Add feedback to context for next iteration
            context.add_feedback(f"Previous attempt had confidence {confidence:.2f}")
            iteration += 1
        
        # Return best effort after max iterations
        return result
    
    def _evaluate_confidence(self, result, context):
        # Implement confidence scoring based on:
        # - Number of successful tool calls
        # - Amount of evidence gathered
        # - Consistency of findings
        pass
```

### Phase 3: Graph-Based Complex Workflows

For advanced use cases, implement graph workflows:

```python
class BinaryAnalysisGraph:
    """Multi-stage binary analysis with iterative refinement."""
    
    def __init__(self):
        self.nodes = [
            InitialTriage,
            SymbolAnalysis,
            StringAnalysis,
            BehaviorAnalysis,
            ConfidenceEvaluation,
            DeepDive,
            FinalReport
        ]
        self.graph = Graph(nodes=self.nodes)
    
    async def analyze(self, binary_path, question):
        state = AnalysisState(
            binary_path=binary_path,
            question=question,
            findings={},
            confidence=0.0
        )
        
        async with self.graph.iter(InitialTriage(), state=state) as run:
            async for node in run:
                print(f"Stage: {node.__class__.__name__}")
                
                # Allow early termination if high confidence
                if state.confidence > 0.9:
                    break
        
        return run.result
```

## Implementation Priority

1. **Immediate (Phase 1)**: Add retry logic to critical tools
   - Symbol search
   - String search
   - Function analysis
   
2. **Short-term (Phase 2)**: Implement iterative wrapper
   - Confidence scoring
   - Feedback incorporation
   - Iteration limits
   
3. **Long-term (Phase 3)**: Graph workflows for complex analysis
   - Multi-stage investigation
   - State persistence
   - Visual workflow debugging

## Benefits

- **Better accuracy**: Agents can refine understanding iteratively
- **Resilience**: Automatic recovery from tool failures
- **Transparency**: Clear iteration paths for debugging
- **Flexibility**: Different strategies for different question types
- **User experience**: Progressive results instead of single failure

## Next Steps

1. Start with adding `ModelRetry` to existing tools
2. Implement confidence scoring in MemoryContext
3. Create `IterativeAnalysisAgent` wrapper class
4. Test with complex malware analysis scenarios
5. Consider graph workflows for multi-stage analysis