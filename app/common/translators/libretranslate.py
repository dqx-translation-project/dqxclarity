from common.measure import measure_duration
from loguru import logger as log

import requests


class LibreTranslate:
    def __init__(self, base_url: str, api_key: str = None) -> None:
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        """Translates a list of phrases from Japanese to English using LibreTranslate."""
        try:
            results = []
            for phrase in text:
                url = f"{self.base_url}/translate"
                data = {
                    'q': phrase,
                    'source': 'ja',
                    'target': 'en',
                    'format': 'text'
                }
                if self.api_key:
                    data['api_key'] = self.api_key
                response = self.session.post(url, json=data)
                response.raise_for_status()
                result = response.json()
                if 'translatedText' in result:
                    results.append(result['translatedText'])
                else:
                    log.error(f"Unexpected response format from LibreTranslate: {result}")
                    results.append("")
            return results
        except requests.exceptions.RequestException as e:
            log.error(f"Network error during LibreTranslate request: {e}")
            return []
        except Exception as e:
            log.error(f"Error during LibreTranslate request: {e}")
            return []
