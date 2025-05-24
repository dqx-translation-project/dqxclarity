from common.measure import measure_duration
from googleapiclient.discovery import build
from loguru import logger


# uses Google's official Translate API to send translations.
# requires you to set up a GCP project, enable the Translate API service and obtain
# an API key to use.
class GoogleTranslate:
    def __init__(self, api_key: str) -> None:
        self.service = build("translate", "v2", developerKey=api_key)


    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            response = self.service.translations().list(source="ja", target="en", format="text", q=text).execute()

            results = []
            for result in response["translations"]:
                results.append(result["translatedText"])

            return results
        except Exception as e:
            logger.error(f"Error during request: {e}")
            return []
