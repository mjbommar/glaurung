"""Configuration wrapper for LLM providers (compat)."""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict
from pydantic_ai import Agent

logger = logging.getLogger(__name__)


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

    def create_agent(
        self,
        system_prompt: str,
        model: Optional[str] = None,
        output_type: Optional[type] = None,
        **kwargs,
    ) -> Agent:
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
        agent_kwargs = {"model": model, "system_prompt": system_prompt}
        if output_type:
            agent_kwargs["output_type"] = output_type
        agent_kwargs.update(kwargs)
        return Agent(**agent_kwargs)

    def available_models(self) -> Dict[str, bool]:
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
