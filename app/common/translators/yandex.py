import requests
import time
import uuid
from common.measure import measure_duration
from loguru import logger as log


class YandexTranslate:
    _URL = "https://translate.yandex.net/api/v1/tr.json/translate"
    _HEADERS = {"User-Agent": "ru.yandex.translate/3.20.2024"}
    _UCID_TTL = 360

    def __init__(self, api_key: str = "") -> None:
        self._ucid: str | None = None
        self._ucid_time: float = 0

    def _get_ucid(self) -> str:
        if self._ucid is None or (time.time() - self._ucid_time) > self._UCID_TTL:
            self._ucid = uuid.uuid4().hex
            self._ucid_time = time.time()
        return self._ucid

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            results = []
            ucid = self._get_ucid()
            for phrase in text:
                response = requests.post(
                    self._URL,
                    params={"ucid": ucid, "srv": "android", "format": "text"},
                    data={"text": phrase, "lang": "ja-en"},
                    headers=self._HEADERS,
                )
                response.raise_for_status()
                data = response.json()
                if data.get("code") == 200:
                    results.append(data["text"][0])
                else:
                    log.warning(f"Yandex returned code {data.get('code')}")
                    results.append("")
            return results
        except Exception as e:
            log.error(f"Error during request: {e}")
            return []
