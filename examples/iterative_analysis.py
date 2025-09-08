#!/usr/bin/env python3
"""Example of iterative agent refinement for binary analysis."""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import glaurung as g
from glaurung.llm.agents.iterative import (
    IterativeAgent,
    RefinementStrategy,
    create_iterative_memory_agent
)
from glaurung.llm.context import MemoryContext, Budgets
from glaurung.llm.kb.adapters import import_triage


async def analyze_binary_with_refinement(binary_path: str, question: str):
    """Demonstrate iterative refinement for binary analysis."""
    
    print(f"🔍 Analyzing: {binary_path}")
    print(f"❓ Question: {question}")
    print("-" * 60)
    
    # Perform initial triage
    print("📊 Running triage analysis...")
    artifact = g.triage.analyze_path(
        binary_path,
        _max_read_bytes=10_485_760,
        _max_file_size=104_857_600,
        _max_recursion_depth=1,
    )
    
    # Set up context with budgets
    budgets = Budgets(
        max_functions=10,
        max_instructions=50_000,
        max_disasm_window=4096,
        max_read_bytes=10_485_760,
        max_file_size=104_857_600,
    )
    
    context = MemoryContext(
        file_path=binary_path,
        artifact=artifact,
        session_id="iterative_demo",
        allow_expensive=True,
        budgets=budgets
    )
    
    # Import triage data into KB
    import_triage(context.kb, artifact, binary_path)
    
    # Configure refinement strategy
    strategy = RefinementStrategy(
        max_iterations=3,  # Up to 3 refinement iterations
        min_confidence=0.75,  # Target 75% confidence
        backoff_factor=1.2,  # Small backoff between iterations
        require_evidence=True,
        allow_partial_results=True
    )
    
    # Create iterative agent
    print("🤖 Creating iterative analysis agent...")
    agent = await create_iterative_memory_agent(
        model=None,  # Use default model
        strategy=strategy
    )
    
    # Run analysis with refinement
    print("🔄 Starting iterative analysis...")
    print()
    
    try:
        result = await agent.run_with_refinement(
            question=question,
            context=context
        )
        
        # Display results
        print("\n" + "=" * 60)
        print("📋 ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"✅ Answer: {result.answer}")
        print(f"🎯 Confidence: {result.confidence:.1%}")
        print(f"🔄 Iterations used: {result.iterations_used}")
        print(f"📊 Evidence pieces: {result.evidence_count}")
        print(f"🛠️ Tools used: {', '.join(result.tools_used) if result.tools_used else 'None'}")
        
        if result.refinement_path:
            print("\n📍 Refinement Path:")
            for step in result.refinement_path:
                print(f"  - {step}")
        
        # Show KB statistics
        kb_nodes = sum(1 for _ in context.kb.nodes())
        kb_edges = sum(1 for _ in context.kb.edges())
        print(f"\n📚 Knowledge Base: {kb_nodes} nodes, {kb_edges} edges")
        
        return result
        
    except RuntimeError as e:
        print(f"\n❌ Analysis failed: {e}")
        return None


async def main():
    """Run example analysis."""
    
    # Example 1: Simple binary analysis
    if len(sys.argv) > 2:
        binary_path = sys.argv[1]
        question = " ".join(sys.argv[2:])
    else:
        # Default example
        binary_path = "/bin/ls"
        question = "What are the main security features and potential risks of this binary?"
    
    # Validate binary exists
    if not Path(binary_path).exists():
        print(f"❌ Error: Binary not found: {binary_path}")
        print(f"Usage: {sys.argv[0]} <binary_path> <question>")
        sys.exit(1)
    
    # Run analysis
    result = await analyze_binary_with_refinement(binary_path, question)
    
    if result:
        print("\n✨ Analysis completed successfully!")
    else:
        print("\n⚠️ Analysis completed with warnings.")


if __name__ == "__main__":
    asyncio.run(main())