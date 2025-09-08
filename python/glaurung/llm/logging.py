"""Logging integration for LLM operations (compat)."""

import logging
import time
from typing import Optional, Dict, Any
from functools import wraps
from pydantic_ai.usage import Usage

logger = logging.getLogger(__name__)


class LLMLogger:
    def __init__(self, enable_logging: bool = True, log_level: str = "INFO"):
        self.enable_logging = enable_logging
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        if self.enable_logging:
            logger.setLevel(self.log_level)
        self.total_requests = 0
        self.total_tokens = 0
        self.total_cost = 0.0

    def log_request(self, model: str, prompt: str, system_prompt: Optional[str] = None):
        if not self.enable_logging:
            return
        self.total_requests += 1
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"LLM Request #{self.total_requests}")
            logger.debug(f"  Model: {model}")
            if system_prompt:
                logger.debug(f"  System: {system_prompt[:100]}...")
            logger.debug(f"  Prompt: {prompt[:200]}...")
        else:
            logger.info(f"LLM Request #{self.total_requests} to {model}")

    def log_response(
        self,
        model: str,
        response: Any,
        usage: Optional[Usage] = None,
        duration: Optional[float] = None,
    ):
        if not self.enable_logging:
            return
        if hasattr(response, "usage"):
            usage = response.usage
        if usage:
            if hasattr(usage, "total_tokens"):
                self.total_tokens += usage.total_tokens
            elif hasattr(usage, "request_tokens") and hasattr(usage, "response_tokens"):
                self.total_tokens += usage.request_tokens + usage.response_tokens
        if logger.isEnabledFor(logging.DEBUG):
            if hasattr(response, "output"):
                logger.debug(f"  Output: {str(response.output)[:200]}...")
            else:
                logger.debug(f"  Response: {str(response)[:200]}...")
            if duration:
                logger.debug(f"  Duration: {duration:.2f}s")
        else:
            tokens_str = (
                f", tokens: {usage.total_tokens if hasattr(usage, 'total_tokens') else 'unknown'}"
                if usage
                else ""
            )
            duration_str = f", duration: {duration:.2f}s" if duration else ""
            logger.info(f"LLM Response from {model}{tokens_str}{duration_str}")

    def log_error(self, model: str, error: Exception):
        if not self.enable_logging:
            return
        logger.error(f"LLM Error from {model}: {error}")

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "total_tokens": self.total_tokens,
            "total_cost": self.total_cost,
        }

    def reset_stats(self):
        self.total_requests = 0
        self.total_tokens = 0
        self.total_cost = 0.0


_llm_logger: Optional[LLMLogger] = None


def get_logger() -> LLMLogger:
    global _llm_logger
    if _llm_logger is None:
        _llm_logger = LLMLogger()
    return _llm_logger


def set_logger(logger_instance: LLMLogger):
    global _llm_logger
    _llm_logger = logger_instance


def logged_agent_run(func):
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        llm_logger = get_logger()
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            model = "unknown"
            if hasattr(result, "model"):
                model = str(result.model)
            elif len(args) > 0 and hasattr(args[0], "model"):
                model = str(args[0].model)
            llm_logger.log_response(model, result, duration=duration)
            return result
        except Exception as e:
            llm_logger.log_error("unknown", e)
            raise

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        llm_logger = get_logger()
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            model = "unknown"
            if hasattr(result, "model"):
                model = str(result.model)
            elif len(args) > 0 and hasattr(args[0], "model"):
                model = str(args[0].model)
            llm_logger.log_response(model, result, duration=duration)
            return result
        except Exception as e:
            llm_logger.log_error("unknown", e)
            raise

    import asyncio

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper
