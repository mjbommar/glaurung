"""Example of iterative agent refinement for binary analysis."""

import argparse
import asyncio
from collections.abc import Sequence
from pathlib import Path

import glaurung as g
from glaurung.llm.agents.iterative import (
    RefinementStrategy,
    create_iterative_memory_agent,
)
from glaurung.llm.config import get_config
from glaurung.llm.context import Budgets, MemoryContext
from glaurung.llm.kb.adapters import import_triage


async def analyze_binary_with_refinement(
    binary_path: str, question: str, model: str | None = None
):
    """Demonstrate iterative refinement for binary analysis."""

    print(f"🔍 Analyzing: {binary_path}")
    print(f"❓ Question: {question}")
    print("-" * 60)

    # Perform initial triage
    print("📊 Running triage analysis...")
    artifact = g.triage.analyze_path(binary_path)

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
        budgets=budgets,
    )

    # Import triage data into KB
    import_triage(context.kb, artifact, binary_path)

    # Configure refinement strategy
    strategy = RefinementStrategy(
        max_iterations=3,  # Up to 3 refinement iterations
        min_confidence=0.75,  # Target 75% confidence
        backoff_factor=1.2,  # Small backoff between iterations
        require_evidence=True,
        allow_partial_results=True,
    )

    # Create iterative agent
    print("🤖 Creating iterative analysis agent...")
    agent = await create_iterative_memory_agent(
        model=model,
        strategy=strategy,
    )

    # Run analysis with refinement
    print("🔄 Starting iterative analysis...")
    print()

    try:
        result = await agent.run_with_refinement(question=question, context=context)

        # Display results
        print("\n" + "=" * 60)
        print("📋 ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"✅ Answer: {result.answer}")
        print(f"🎯 Confidence: {result.confidence:.1%}")
        print(f"🔄 Iterations used: {result.iterations_used}")
        print(f"📊 Evidence pieces: {result.evidence_count}")
        print(
            f"🛠️ Tools used: {', '.join(result.tools_used) if result.tools_used else 'None'}"
        )

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


async def main(argv: Sequence[str] | None = None) -> int:
    """Run the model-backed example against an explicit or checked-in binary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary",
        nargs="?",
        type=Path,
        default=Path(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
        ),
    )
    parser.add_argument(
        "--question",
        default="What security-relevant behavior is supported by binary evidence?",
    )
    parser.add_argument("--model")
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    if not any(get_config().available_models().values()):
        print("No supported model is configured; this example is model-backed.")
        return 3

    result = await analyze_binary_with_refinement(
        str(args.binary), args.question, model=args.model
    )

    if result:
        print("\n✨ Analysis completed successfully!")
        return 0
    else:
        print("\n⚠️ Analysis completed with warnings.")
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
