from common import measure
from common.measure import measure_duration
from loguru import logger

import deepl


# uses DeepL's official Translate API to send translations.
# requires creating a developer API account to obtain an API key.
class DeepLTranslate():
    def __init__(self, api_key: str) -> None:
        self.translator = deepl.Translator(api_key)


    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            response = self.translator.translate_text(
                text=text,
                source_lang="ja",
                target_lang="en-us",
                preserve_formatting=True
            )

            results = []
            for result in response:
                results.append(result.text)

            return results
        except Exception as e:
            logger.error(f"Error during request: {e}")
            return []
