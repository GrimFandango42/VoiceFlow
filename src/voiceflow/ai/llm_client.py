"""
Local LLM Client for VoiceFlow AI Features

Supports Ollama for local inference with fast, small models.
"""

import logging
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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

    def is_available(self) -> bool:
        """Check if Ollama server is running"""
        if self._available is not None:
            return self._available

        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=2) as response:
                self._available = response.status == 200
        except Exception:
            self._available = False

        return self._available

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
            logger.warning(f"Ollama request failed: {e}")
            return LLMResponse(
                text=prompt,
                success=False,
                error=str(e),
            )
        except Exception as e:
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
        # Prefer smaller, faster models for transcription cleanup
        if model is None:
            # Try to find a suitable model
            temp_client = OllamaClient()
            available = temp_client.list_models()

            # Prefer smaller models for speed
            preferred = [
                "llama3.2:3b", "llama3.2:1b",
                "qwen2.5:3b", "qwen2.5-coder:7b",
                "phi3:mini", "gemma2:2b",
            ]

            for pref in preferred:
                if any(pref in m for m in available):
                    model = next(m for m in available if pref in m)
                    break

            if model is None and available:
                model = available[0]
            elif model is None:
                model = "llama3.2:3b"  # Default

        _client = OllamaClient(model=model)
        logger.info(f"LLM client initialized with model: {model}")

    return _client
