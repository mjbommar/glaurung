"""Configuration wrapper for LLM providers (compat)."""

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    # Required project default: OpenAI gpt-5.4-mini with service_tier='flex'.
    # User-mandated for every Glaurung/ASB LLM call (binary triage, vuln
    # discovery, critic, sweep). gpt-5.4-mini avoids Anthropic IPM
    # ceilings on parallel sweeps; the OpenAI 128-tool cap is handled
    # by L5 routing (`--route` on the CLI / `tool_filter=` on
    # register_analysis_tools), which keeps the per-question tool count
    # under 30. Anthropic / larger models remain available as explicit
    # `--model` overrides for one-off interactive use.
    default_model: str = field(default="openai:gpt-5.4-mini")
    fallback_model: str = field(default="anthropic:claude-haiku-4-5")
    summarizer_model: str = field(default="openai:gpt-5.4-mini")
    risk_scorer_model: str = field(default="openai:gpt-5.4-mini")
    ioc_model: str = field(default="openai:gpt-5.4-mini")

    # OpenAI service tier. 'flex' = cheaper / higher-latency tolerated;
    # 'default' = standard latency. Required default per project policy.
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
            "GLAURUNG_OPENAI_SERVICE_TIER", self.openai_service_tier,
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
        """Return the best model available given current credentials.

        Anthropic Claude Opus 4.7 is preferred; we fall back to OpenAI's
        GPT-5.5 when the Anthropic key is missing. Returns the configured
        ``default_model`` when neither provider is available so callers
        that only want to *construct* an Agent (e.g. tests) still get a
        sensible value.
        """
        avail = self.available_models()
        if avail.get("anthropic"):
            return self.default_model
        if avail.get("openai"):
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
