from common.measure import measure_duration
from loguru import logger as log
from socket import timeout

import deepl


# uses DeepL's official Translate API to send translations.
# requires creating a developer API account to obtain an API key.
class DeepLTranslate():
    def __init__(self, api_key: str) -> None:
        # don't retry on timeout to avoid hanging up the thread longer than we need to.
        deepl.http_client.max_network_retries = 1
        deepl.http_client.min_connection_timeout = 3

        self.translator = deepl.Translator(auth_key=api_key, send_platform_info=False)


    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            response = self.translator.translate_text(
                text=text,
                source_lang="ja",
                target_lang="en-us",
                preserve_formatting=True,
            )

            results = []
            for result in response:
                results.append(result.text)


            return results
        except Exception as e:
            log.error(f"Error during request: {e}")
            return []
