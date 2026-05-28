"""Configuration wrapper for LLM providers (compat)."""

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# Auto-load .env from the cwd (and any parent up to filesystem root) the
# moment this module is imported. Without this, non-interactive shells
# (background agents, CI, test runners, subprocess.Popen) see
# OPENAI_API_KEY / ANTHROPIC_API_KEY as unset whenever the operator's
# keys live in ~/.bashrc rather than .env, and every LLM call silently
# falls back to heuristic output. The fail-loud guard in
# `tools/_llm_helpers.py` (require_llm + WARNING) catches this, but
# preventing it in the first place is the right fix.
#
# `find_dotenv()` walks parent directories from cwd, so running glaurung
# from any subtree of a repo that has a .env file Just Works.
try:
    from dotenv import find_dotenv, load_dotenv  # type: ignore
    _dotenv_path = find_dotenv(usecwd=True)
    if _dotenv_path:
        load_dotenv(_dotenv_path, override=False)
        logger.debug("Loaded .env from %s", _dotenv_path)
except ImportError:
    # python-dotenv not installed; environment-only mode (existing
    # behavior pre-2026-05-27).
    pass


@dataclass
class LLMConfig:
    # REQUIRED project default per CLAUDE.md: openai:gpt-5.4-mini with
    # service_tier="flex". Do NOT silently swap to Claude when both keys
    # are set; cost lives in this default and the project has made an
    # explicit decision. Anthropic Claude stays available as an
    # explicit-override target via `--model anthropic:claude-...` on
    # the CLI, or via the GLAURUNG_LLM_MODEL env var.
    default_model: str = field(default="openai:gpt-5.4-mini")
    fallback_model: str = field(default="anthropic:claude-haiku-4-5")
    summarizer_model: str = field(default="openai:gpt-5.4-mini")
    risk_scorer_model: str = field(default="openai:gpt-5.4-mini")
    ioc_model: str = field(default="openai:gpt-5.4-mini")

    # OpenAI service tier ("flex" | "default" | "priority"). Higher-
    # level callers (findings runner, critic, name-func) plumb this
    # through ModelSettings.extra_body so the request gets the cheaper
    # flex tier with its separate quota.
    openai_service_tier: str = field(default="flex")

    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None

    temperature: float = 0.3
    max_tokens: Optional[int] = None

    # --- Per-Agent.run() budget defaults (F1) ---
    #
    # pydantic-ai's built-in UsageLimits.request_limit is 50, which is
    # both too generous AND undefended -- a confused tool-using agent
    # can burn 50 round-trips of full-prompt input tokens before
    # giving up. The values below are tuned for May-2026 models that
    # routinely emit 64K+ output tokens and have million-token context
    # windows; the request_limit fail-fast cap is the new default.
    #
    # Override via env (one-off) or per-call (build_usage_limits(...)).
    default_request_limit: int = 12         # max tool-turns per Agent.run()
    default_input_tokens_limit: int = 400_000
    default_total_tokens_limit: int = 500_000
    default_max_output_tokens: int = 32_768

    enable_logging: bool = True
    log_level: str = "INFO"
    fallback_on_error: bool = True
    cache_responses: bool = False

    def __post_init__(self):
        self.openai_api_key = os.getenv("OPENAI_API_KEY", self.openai_api_key)
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", self.anthropic_api_key)
        self.google_api_key = os.getenv("GOOGLE_API_KEY", self.google_api_key)
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", self.gemini_api_key)
        self.default_model = os.getenv("GLAURUNG_LLM_MODEL", self.default_model)
        self.openai_service_tier = os.getenv(
            "GLAURUNG_OPENAI_SERVICE_TIER", self.openai_service_tier
        )
        if temp_env := os.getenv("GLAURUNG_LLM_TEMPERATURE"):
            try:
                self.temperature = float(temp_env)
            except ValueError:
                logger.warning(f"Invalid temperature value: {temp_env}")

        # Budget envs (F1). Each is parsed as int; bad values log + ignore.
        for env_name, attr in (
            ("GLAURUNG_REQUEST_LIMIT", "default_request_limit"),
            ("GLAURUNG_INPUT_TOKENS_LIMIT", "default_input_tokens_limit"),
            ("GLAURUNG_TOTAL_TOKENS_LIMIT", "default_total_tokens_limit"),
            ("GLAURUNG_MAX_OUTPUT_TOKENS", "default_max_output_tokens"),
        ):
            if raw := os.getenv(env_name):
                try:
                    setattr(self, attr, int(raw))
                except ValueError:
                    logger.warning(f"Invalid {env_name} value: {raw!r}")

    def create_agent(
        self,
        system_prompt: str,
        model: Optional[str] = None,
        output_type: Optional[type] = None,
        **kwargs: Any,
    ) -> Any:
        from pydantic_ai import Agent

        model = model or self.default_model
        if self.openai_api_key and "openai" in model:
            os.environ["OPENAI_API_KEY"] = self.openai_api_key
        if self.anthropic_api_key and "anthropic" in model:
            os.environ["ANTHROPIC_API_KEY"] = self.anthropic_api_key
        if self.google_api_key and "gemini" in model:
            os.environ["GOOGLE_API_KEY"] = self.google_api_key
        if self.gemini_api_key and "gemini" in model:
            os.environ["GEMINI_API_KEY"] = self.gemini_api_key
        if self.enable_logging:
            logger.info(f"Creating agent with model: {model}")
        agent_kwargs: dict[str, Any] = {
            "model": model,
            "system_prompt": system_prompt,
        }
        if output_type:
            agent_kwargs["output_type"] = output_type
        agent_kwargs.update(kwargs)
        return Agent(**agent_kwargs)

    def available_models(self) -> dict[str, bool]:
        return {
            "openai": bool(self.openai_api_key or os.getenv("OPENAI_API_KEY")),
            "anthropic": bool(self.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")),
            "gemini": bool(
                self.google_api_key
                or self.gemini_api_key
                or os.getenv("GOOGLE_API_KEY")
                or os.getenv("GEMINI_API_KEY")
            ),
        }

    def preferred_model(self) -> str:
        """Return the project-required default model when its provider is
        available; otherwise fall back.

        Per CLAUDE.md / feedback-llm-model-default, the project default is
        ``openai:gpt-5.4-mini`` with ``service_tier=flex``. Anthropic
        Claude is an explicit-override target via ``--model
        anthropic:claude-...`` -- NEVER a silent swap.

        Previous version of this function inverted the if-clauses: it
        returned the OpenAI default when an Anthropic key was set, and
        returned the Anthropic fallback when only an OpenAI key was set.
        That caused every Layer-0 / Tool #14 call to route to Anthropic
        whenever ANTHROPIC_API_KEY was unset -- the opposite of intent.
        Fixed 2026-05-26.
        """
        avail = self.available_models()
        default_provider = self.default_model.split(":", 1)[0]
        if avail.get(default_provider):
            return self.default_model
        # Default provider unavailable. Fall back if its provider is up;
        # otherwise return default_model anyway so callers that only need
        # to construct an Agent (e.g. tests) still get a sensible value.
        fallback_provider = self.fallback_model.split(":", 1)[0]
        if avail.get(fallback_provider):
            return self.fallback_model
        return self.default_model


_config: Optional[LLMConfig] = None


def get_config() -> LLMConfig:
    global _config
    if _config is None:
        _config = LLMConfig()
    return _config


def set_config(config: LLMConfig) -> None:
    global _config
    _config = config
