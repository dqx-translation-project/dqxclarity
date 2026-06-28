import requests
from common.config import UserConfig
from common.measure import measure_duration
from loguru import logger as log


_PROMPT_TEMPLATE = (
    "Translate the following Dragon Quest X dialogue from Japanese to {lang}. "
    'Keep it localized and immersive. Return only the translated text.\n\n"{text}"'
)


class OllamaTranslate:
    def __init__(self, api_key: str = "") -> None:
        cfg = UserConfig()
        self.url = cfg.ollama_url.rstrip("/") + "/api/generate"
        self.model = cfg.ollama_model
        self.lang = cfg.target_language_name

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            results = []
            for phrase in text:
                payload = {
                    "model": self.model,
                    "prompt": _PROMPT_TEMPLATE.format(lang=self.lang, text=phrase),
                    "temperature": 0.1,
                    "stream": False,
                }
                response = requests.post(self.url, json=payload, timeout=60)
                response.raise_for_status()
                translated = response.json().get("response", "").strip().strip('"')
                results.append(translated)
            return results
        except Exception as e:
            log.error(f"Error during request: {e}")
            return []
