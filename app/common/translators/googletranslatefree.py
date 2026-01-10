from common.measure import measure_duration
from loguru import logger as log

import html
import re
import requests


# uses the free Google Translate mobile web interface to send translations.
# parses the html response to extract the translated text.
class GoogleTranslateFree:
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.108 Mobile Safari/537.36"
    }

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(GoogleTranslateFree.headers)

    def __parse_response(self, response: str) -> str:
        """Parses the HTML response to extract the translated text."""
        match = re.search(r'<div class="result-container">(.*?)</div>', response, re.DOTALL)
        if not match:
            return ""

        text = match.group(1).strip()
        return html.unescape(text)

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        """Translates a list of phrases from Japanese to English."""
        try:
            results = []
            for phrase in text:
                response = self.session.get(f"https://translate.google.com/m?hl=en&sl=ja&tl=en&q={phrase}")
                response.raise_for_status()
                results.append(self.__parse_response(response.text))
            return results
        except Exception as e:
            log.error(f"Error during request: {e}")
            return []
