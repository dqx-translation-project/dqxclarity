import requests
from common.config import UserConfig
from common.measure import measure_duration
from loguru import logger as log


# uses Google's unofficial translate_a/single endpoint (client=gtx), which requires no API key.
# this is the "translate-pa" family of free endpoints — more reliable than HTML scraping.
class GoogleTranslatePa:
    _URL = "https://translate.googleapis.com/translate_a/single"

    def __init__(self, api_key: str = "") -> None:
        self.session = requests.Session()
        self.target = UserConfig().target_language

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            results = []
            for phrase in text:
                response = self.session.get(
                    self._URL,
                    params={"client": "gtx", "sl": "ja", "tl": self.target, "dt": "t", "q": phrase},
                )
                response.raise_for_status()
                data = response.json()
                translated = "".join(segment[0] for segment in data[0] if segment[0])
                results.append(translated)
            return results
        except Exception as e:
            log.error(f"Error during request: {e}")
            return []
