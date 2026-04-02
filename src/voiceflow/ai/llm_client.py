"""
Local LLM Client for VoiceFlow AI Features

Supports Ollama for local inference with fast, small models.
"""

import logging
import json
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def _is_text_generation_model(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    return "embed" not in lowered and "embedding" not in lowered


@dataclass
class LLMResponse:
    """Response from LLM"""
    text: str
    success: bool
    error: Optional[str] = None
    model: str = ""
    duration_ms: float = 0.0


class OllamaClient:
    """
    Client for Ollama local LLM server.

    Uses HTTP API for simplicity (no additional dependencies).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "qwen2.5-coder:7b",
        timeout: float = 30.0,
    ):
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self._available = None
        self._availability_checked_at = 0.0
        self._availability_retry_seconds = 30.0
        self._availability_cache_seconds = 300.0

    def is_available(self) -> bool:
        """Check if Ollama server is running"""
        if self._available is not None:
            age = time.time() - float(self._availability_checked_at or 0.0)
            ttl = self._availability_cache_seconds if self._available else self._availability_retry_seconds
            if age < ttl:
                return self._available

        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=2) as response:
                self._available = response.status == 200
        except Exception:
            self._available = False
        finally:
            self._availability_checked_at = time.time()

        return self._available

    def refresh_availability(self) -> bool:
        """Force a fresh availability probe."""
        self._availability = None
        self._availability_checked_at = 0.0
        return self.is_available()

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 500,
    ) -> LLMResponse:
        """
        Generate text using Ollama.

        Args:
            prompt: The user prompt
            system: Optional system prompt
            temperature: Sampling temperature (0.0 = deterministic)
            max_tokens: Maximum tokens to generate

        Returns:
            LLMResponse with generated text
        """
        if not self.is_available():
            return LLMResponse(
                text=prompt,  # Return original on failure
                success=False,
                error="Ollama not available",
            )

        try:
            # Build request
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            if system:
                payload["system"] = system

            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                f"{self.base_url}/api/generate",
                data=data,
                headers={"Content-Type": "application/json"},
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode('utf-8'))

            return LLMResponse(
                text=result.get("response", "").strip(),
                success=True,
                model=result.get("model", self.model),
                duration_ms=result.get("total_duration", 0) / 1_000_000,  # ns to ms
            )

        except urllib.error.URLError as e:
            self._available = False
            self._availability_checked_at = time.time()
            logger.warning(f"Ollama request failed: {e}")
            return LLMResponse(
                text=prompt,
                success=False,
                error=str(e),
            )
        except Exception as e:
            self._available = False
            self._availability_checked_at = time.time()
            logger.error(f"LLM generation error: {e}")
            return LLMResponse(
                text=prompt,
                success=False,
                error=str(e),
            )

    def list_models(self) -> list:
        """List available models"""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []


# Global client instance (lazy initialization)
_client: Optional[OllamaClient] = None


def get_llm_client(model: Optional[str] = None) -> OllamaClient:
    """Get or create the global LLM client"""
    global _client

    if _client is None or (model and _client.model != model):
        temp_client = OllamaClient()
        available = temp_client.list_models()
        generation_models = [name for name in available if _is_text_generation_model(name)]

        # Prefer smaller, faster models for transcription cleanup
        preferred = [
            "llama3.2:3b", "llama3.2:1b",
            "llama3.1", "phi3", "gemma2",
            "qwen2.5-coder", "qwen2.5",
            "deepseek-r1",
        ]

        if model:
            exact_match = next((m for m in generation_models if m == model), None)
            partial_match = next((m for m in generation_models if model in m or m in model), None)
            if exact_match:
                model = exact_match
            elif partial_match:
                model = partial_match
            elif generation_models:
                fallback = None
                for pref in preferred:
                    fallback = next((m for m in generation_models if pref in m), None)
                    if fallback:
                        break
                model = fallback or generation_models[0]
                logger.warning("Configured ai_model not installed locally; falling back to %s", model)
        else:
            for pref in preferred:
                if any(pref in m for m in generation_models):
                    model = next(m for m in generation_models if pref in m)
                    break

            if model is None and generation_models:
                model = generation_models[0]
            elif model is None:
                model = "llama3.2:3b"  # Default

        _client = OllamaClient(model=model)
        logger.info(f"LLM client initialized with model: {model}")

    return _client
