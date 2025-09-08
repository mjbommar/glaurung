"""Natural language Q&A command for binary analysis."""

import argparse
import asyncio
import sys
from typing import List, Dict, Any

import glaurung as g
from .base import BaseCommand
from ...llm.agents.factory import AnalysisAgentFactory
from ...llm.agents.base import ModelHyperparameters
from ...llm.context import MemoryContext, Budgets
from ...llm.kb.adapters import import_triage as kb_import_triage
from ...llm.config import get_config


class AskCommand(BaseCommand):
    """Command for natural language Q&A about binaries."""

    def get_name(self) -> str:
        """Return the command name."""
        return "ask"

    def get_help(self) -> str:
        """Return the command help text."""
        return "Ask natural language questions about a binary"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments."""
        parser.add_argument("path", help="Path to binary file to analyze")

        # Question input options
        question_group = parser.add_mutually_exclusive_group()
        question_group.add_argument(
            "-a", "--ask", dest="question", help="Question to ask about the binary"
        )
        question_group.add_argument(
            "-m",
            "--multiple",
            dest="questions",
            nargs="+",
            help="Multiple questions to ask",
        )
        question_group.add_argument(
            "-i", "--interactive", action="store_true", help="Interactive Q&A mode"
        )
        question_group.add_argument(
            "--stdin",
            action="store_true",
            help="Read questions from stdin (one per line)",
        )

        # Analysis options
        parser.add_argument(
            "--agent",
            choices=["memory", "simple"],
            default="memory",
            help="Agent backend to use (default: memory)",
        )
        parser.add_argument(
            "--strategy",
            choices=["single", "iterative", "auto"],
            default="auto",
            help="Execution strategy: single-pass, iterative refinement, or auto-select (default: auto)",
        )
        parser.add_argument(
            "--max-iterations",
            type=int,
            default=5,
            help="Max iterations for iterative strategy (default: 5)",
        )
        parser.add_argument(
            "--min-confidence",
            type=float,
            default=0.7,
            help="Minimum confidence threshold for iterative strategy (default: 0.7)",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=120,
            help="Maximum execution time in seconds (default: 120)",
        )
        parser.add_argument(
            "--show-tools",
            action="store_true",
            help="Show tool calls and results (verbose mode)",
        )
        parser.add_argument(
            "--show-plan", action="store_true", help="Show LLM planning/reasoning"
        )
        parser.add_argument(
            "--model", help=f"Model to use (default: {get_config().default_model})"
        )

        # Triage options
        parser.add_argument(
            "--max-read-bytes",
            type=int,
            default=10_485_760,
            help="Max bytes to read during triage (default: 10MB)",
        )
        parser.add_argument(
            "--max-file-size",
            type=int,
            default=104_857_600,
            help="Max file size (default: 100MB)",
        )
        parser.add_argument(
            "--quick",
            action="store_true",
            help="Quick mode: ask common malware analysis questions",
        )
        # Budgets for memory agent
        parser.add_argument(
            "--max-functions", type=int, default=5, help="Max functions to analyze"
        )
        parser.add_argument(
            "--max-instructions",
            type=int,
            default=50_000,
            help="Max instructions budget",
        )
        parser.add_argument(
            "--disasm-window",
            type=int,
            default=4096,
            help="Max disassembly window bytes",
        )

    def _serialize_args(self, args: Any) -> Any:
        """Serialize tool arguments for display."""
        if args is None:
            return {}
        if isinstance(args, (str, int, float, bool)):
            return args
        if isinstance(args, dict):
            return {k: self._serialize_args(v) for k, v in args.items()}
        if isinstance(args, (list, tuple)):
            return [self._serialize_args(v) for v in args]
        # Try to convert to dict if it has __dict__
        if hasattr(args, "__dict__"):
            return self._serialize_args(args.__dict__)
        # Otherwise convert to string
        return str(args)

    def _serialize_result(self, result: Any) -> Any:
        """Serialize tool results for display - NO TRUNCATION!

        LLMs can handle hundreds of thousands of tokens.
        Let them see ALL the data!
        """
        if result is None:
            return None
        if isinstance(result, (str, int, float, bool)):
            return result  # NO TRUNCATION
        if isinstance(result, dict):
            # Serialize ALL keys and values
            return {k: self._serialize_result(v) for k, v in result.items()}
        if isinstance(result, (list, tuple)):
            # Return ALL items - no limits!
            return [self._serialize_result(v) for v in result]
        # Handle Rust/PyO3 objects by trying various conversion methods
        try:
            # Try to_json if available (common for Rust objects)
            if hasattr(result, "to_json"):
                import json

                return json.loads(result.to_json())
        except:
            pass
        try:
            # Try __dict__ if available
            if hasattr(result, "__dict__"):
                return self._serialize_result(result.__dict__)
        except:
            pass
        # Last resort: convert to string - but return FULL string
        return str(result)

    def execute(self, args: argparse.Namespace, formatter) -> int:
        """Execute the command with the given arguments and formatter."""
        # Validate the binary path
        try:
            binary_path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.format_error(str(e))
            return 1

        # Get questions to ask
        questions = self._get_questions(args)
        if not questions:
            formatter.format_error("No questions provided")
            return 1

        # Run async analysis
        try:
            results = asyncio.run(
                self._analyze_binary(str(binary_path), questions, args, formatter)
            )

            # Format and output results
            formatter.format_output(
                {
                    "binary": str(binary_path),
                    "questions": len(questions),
                    "results": results,
                    "show_tools": args.show_tools,
                    "show_plan": args.show_plan,
                }
            )

            return 0

        except KeyboardInterrupt:
            formatter.format_error("Interrupted by user")
            return 130
        except Exception as e:
            if args.verbose:
                import traceback

                traceback.print_exc()
            formatter.format_error(f"Analysis failed: {e}")
            return 1

    def _get_questions(self, args: argparse.Namespace) -> List[str]:
        """Get questions from various input sources."""
        if args.quick:
            # Quick malware analysis questions
            return [
                "Is this binary likely malicious? Explain why or why not.",
                "What are the key indicators of compromise (IOCs)?",
                "Does it have network communication capabilities?",
                "Is it packed or obfuscated?",
                "What suspicious behaviors did you find?",
            ]
        elif args.question:
            return [args.question]
        elif args.questions:
            return args.questions
        elif args.stdin:
            # Read from stdin
            questions = []
            for line in sys.stdin:
                line = line.strip()
                if line:
                    questions.append(line)
            return questions
        elif args.interactive:
            # Interactive mode handled separately
            return ["INTERACTIVE_MODE"]
        else:
            return []

    async def _analyze_binary(
        self,
        binary_path: str,
        questions: List[str],
        args: argparse.Namespace,
        formatter,
    ) -> List[Dict[str, Any]]:
        """Analyze binary with natural language questions."""

        # Check for interactive mode
        if questions == ["INTERACTIVE_MODE"]:
            return await self._interactive_mode(binary_path, args, formatter)

        # Perform triage analysis
        if not args.quiet:
            formatter.format_progress(f"Analyzing {binary_path}...")

        artifact = g.triage.analyze_path(
            binary_path,
            _max_read_bytes=args.max_read_bytes,
            _max_file_size=args.max_file_size,
            _max_recursion_depth=1,
        )

        # Memory-first agent/context setup
        budgets = Budgets(
            max_functions=args.max_functions,
            max_instructions=args.max_instructions,
            max_disasm_window=args.disasm_window,
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
        )
        context = MemoryContext(
            file_path=binary_path,
            artifact=artifact,
            session_id="cli_ask",
            allow_expensive=True,
            budgets=budgets,
        )
        # Initialize KB with triage summary
        kb_import_triage(context.kb, artifact, binary_path)
        # Seed high-signal context to help the agent plan well
        try:
            # Soft-fail: these helpers populate KB; ignore errors
            from ...llm.tools.list_functions import build_tool as _build_list_functions
            from ...llm.tools.map_symbol_addresses import (
                build_tool as _build_map_symbol_addresses,
            )
            from ...llm.tools.map_elf_plt import build_tool as _build_map_elf_plt
            from ...llm.tools.map_elf_got import build_tool as _build_map_elf_got
            from ...llm.tools.map_pe_iat import build_tool as _build_map_pe_iat

            _lf = _build_list_functions()
            _lf.run(
                context,
                context.kb,
                _lf.input_model(max_functions=min(args.max_functions, 16)),
            )
            _sa = _build_map_symbol_addresses()
            _sa.run(context, context.kb, _sa.input_model())
            # Try format-specific maps (they no-op if not applicable)
            for _builder in (_build_map_elf_plt, _build_map_elf_got, _build_map_pe_iat):
                try:
                    _t = _builder()
                    _t.run(context, context.kb, _t.input_model())
                except Exception:
                    pass
        except Exception:
            pass

        # Create agent based on strategy
        if args.strategy == "single":
            agent = AnalysisAgentFactory.create_fast_single_pass_agent(
                model=args.model, timeout=args.timeout
            )
        elif args.strategy == "iterative":
            agent = AnalysisAgentFactory.create_safe_iterative_agent(
                model=args.model,
                max_time_seconds=args.timeout,
                max_tokens=200_000,  # Reasonable default
            )
        else:  # auto
            # Will be handled per-question
            agent = None

        # Set up hyperparameters if needed
        hyperparams = None
        if (
            args.model and "temperature" in args.__dict__
        ):  # If we add temperature arg later
            hyperparams = ModelHyperparameters()

        # Process questions
        results = []
        total = len(questions)

        for i, question in enumerate(questions, 1):
            if not args.quiet:
                formatter.format_progress(f"[{i}/{total}] Processing question...")

            # Run the question based on strategy
            try:
                if args.strategy == "auto":
                    # Use factory's auto-selection
                    analysis_result = (
                        await AnalysisAgentFactory.analyze_with_best_strategy(
                            question,
                            context,
                            prefer_speed=args.quick,
                            require_high_confidence=not args.quick,
                            model=args.model,
                            hyperparameters=hyperparams,
                        )
                    )
                    result_output = analysis_result.answer
                    confidence = analysis_result.confidence
                    iterations = analysis_result.iterations_used
                else:
                    # Use pre-created agent
                    analysis_result = await agent.analyze(
                        question, context, hyperparams
                    )
                    result_output = analysis_result.answer
                    confidence = analysis_result.confidence
                    iterations = analysis_result.iterations_used
            except Exception as e:
                # Provide more detailed error info
                if args.verbose:
                    import traceback

                    traceback.print_exc()
                # Return error as result with actual error message
                error_msg = str(e) if str(e) else f"Unknown error: {type(e).__name__}"
                result_output = f"Analysis failed: {error_msg}"
                confidence = 0.0
                iterations = 0
                # Also print to stderr for visibility
                if not args.quiet:
                    import sys

                    print(f"DEBUG: Analysis error: {error_msg}", file=sys.stderr)

            # Collect result data
            result_data = {
                "question": question,
                "answer": result_output,
                "confidence": confidence,
                "iterations": iterations,
                "tool_calls": [],
                "reasoning": None,
            }

            # Extract tool calls if requested
            if args.show_tools:
                # The new agents track tools internally
                # Only if we have a successful analysis_result
                if "analysis_result" in locals() and hasattr(
                    analysis_result, "tools_used"
                ):
                    for tool_name in analysis_result.tools_used:
                        result_data["tool_calls"].append(
                            {
                                "tool": tool_name,
                                "args": {},
                                "result": "See full output for details",
                            }
                        )

                # Check if context tracked tool calls
                if hasattr(context, "_tool_calls") and context._tool_calls:
                    for call in context._tool_calls:
                        if not any(
                            tc.get("tool") == call.get("tool")
                            for tc in result_data["tool_calls"]
                        ):
                            result_data["tool_calls"].append(call)

                # Skip old message extraction since new agents handle this differently
                if False and hasattr(result, "all_messages"):
                    try:
                        messages = result.all_messages
                        if callable(messages):
                            messages = messages()  # Call if it's a method

                        # Track tool calls by ID for matching with results
                        tool_calls_by_id = {}

                        for msg in messages:
                            # Look for tool calls in message parts
                            if hasattr(msg, "parts"):
                                parts = msg.parts
                                if callable(parts):
                                    parts = parts()  # Call if it's a method
                                for part in parts:
                                    # Check if this is a tool call
                                    if hasattr(part, "tool_name"):
                                        tool_id = getattr(
                                            part, "tool_call_id", id(part)
                                        )
                                        tool_calls_by_id[tool_id] = {
                                            "tool": part.tool_name,
                                            "args": self._serialize_args(
                                                getattr(part, "args", {})
                                            ),
                                        }
                                    # Check if this is a tool result
                                    elif hasattr(part, "tool_call_id"):
                                        tool_id = part.tool_call_id
                                        if tool_id in tool_calls_by_id:
                                            content = getattr(part, "content", None)
                                            if content is not None:
                                                tool_calls_by_id[tool_id]["result"] = (
                                                    self._serialize_result(content)
                                                )

                        # Add all found tool calls to results (if not already tracked)
                        for tool_call in tool_calls_by_id.values():
                            if not any(
                                tc.get("tool") == tool_call["tool"]
                                and tc.get("args") == tool_call.get("args")
                                for tc in result_data["tool_calls"]
                            ):
                                result_data["tool_calls"].append(tool_call)

                    except Exception as e:
                        if args.verbose:
                            import traceback

                            traceback.print_exc()
                        # Add debug info about the error
                        result_data["tool_calls"].append(
                            {
                                "tool": "ERROR_EXTRACTING_TOOLS",
                                "args": {},
                                "result": str(e),
                            }
                        )

            # Extract reasoning/planning if requested
            if args.show_plan:
                # Add metadata about the analysis
                if iterations > 1:
                    result_data["reasoning"] = (
                        f"Performed {iterations} iterations to reach {confidence:.1%} confidence."
                    )
                elif iterations > 0 and confidence >= 0.8:
                    result_data["reasoning"] = (
                        f"High confidence ({confidence:.1%}) achieved in single pass."
                    )
                elif iterations > 0:
                    result_data["reasoning"] = (
                        f"Analysis completed with {confidence:.1%} confidence."
                    )
                else:
                    result_data["reasoning"] = "Analysis encountered an error."

                # Add termination reason if available
                if "analysis_result" in locals() and hasattr(
                    analysis_result, "terminated_reason"
                ):
                    result_data["reasoning"] += (
                        f" Terminated: {analysis_result.terminated_reason.value}"
                    )

            results.append(result_data)

        return results

    async def _interactive_mode(
        self, binary_path: str, args: argparse.Namespace, formatter
    ) -> List[Dict[str, Any]]:
        """Run interactive Q&A mode."""
        formatter.format_info("Entering interactive mode. Type 'exit' to quit.")

        # Perform initial triage
        formatter.format_progress(f"Analyzing {binary_path}...")
        artifact = g.triage.analyze_path(
            binary_path,
            _max_read_bytes=args.max_read_bytes,
            _max_file_size=args.max_file_size,
            _max_recursion_depth=1,
        )

        budgets = Budgets(
            max_functions=args.max_functions,
            max_instructions=args.max_instructions,
            max_disasm_window=args.disasm_window,
            max_read_bytes=args.max_read_bytes,
            max_file_size=args.max_file_size,
        )
        context = MemoryContext(
            file_path=binary_path,
            artifact=artifact,
            session_id="cli_interactive",
            allow_expensive=True,
            budgets=budgets,
        )
        kb_import_triage(context.kb, artifact, binary_path)

        # Use iterative agent for interactive mode (better for exploration)
        agent = AnalysisAgentFactory.create_safe_iterative_agent(
            model=args.model, max_time_seconds=args.timeout
        )

        formatter.format_info("Ready for questions!")

        results = []

        while True:
            try:
                # Get question from user
                question = input("\n❓ Question: ").strip()

                if question.lower() in ["exit", "quit", "q"]:
                    break

                if not question:
                    continue

                # Process question
                formatter.format_progress("Analyzing...")
                analysis_result = await agent.analyze(question, context)

                # Show answer with confidence
                formatter.format_answer(analysis_result.answer)
                if analysis_result.confidence < 0.7:
                    formatter.format_info(
                        f"Note: Low confidence ({analysis_result.confidence:.1%})"
                    )

                # Collect for results
                results.append(
                    {
                        "question": question,
                        "answer": analysis_result.answer,
                        "confidence": analysis_result.confidence,
                        "iterations": analysis_result.iterations_used,
                        "tool_calls": [],
                        "reasoning": None,
                    }
                )

            except KeyboardInterrupt:
                break
            except Exception as e:
                formatter.format_error(f"Error: {e}")

        formatter.format_info("Interactive session ended.")
        return results
