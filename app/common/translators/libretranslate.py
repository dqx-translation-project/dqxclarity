import requests
from common.config import UserConfig
from common.measure import measure_duration
from loguru import logger as log


# uses the LibreTranslate open-source translation API.
# works with the public instance at libretranslate.com or any self-hosted instance.
# api_key is optional — only sent when non-empty (some instances require it, some don't).
class LibreTranslate:
    def __init__(self, api_key: str = "") -> None:
        cfg = UserConfig()
        base = cfg.libretranslate_url.rstrip("/")
        self.url = f"{base}/translate"
        self.api_key = api_key

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            results = []
            for phrase in text:
                payload: dict = {
                    "q": phrase,
                    "source": "ja",
                    "target": "en",
                    "format": "text",
                }
                if self.api_key:
                    payload["api_key"] = self.api_key
                response = requests.post(self.url, data=payload, timeout=30)
                response.raise_for_status()
                translated = response.json().get("translatedText", "")
                results.append(translated)
            return results
        except Exception as e:
            log.error(f"Error during request: {e}")
            return []
