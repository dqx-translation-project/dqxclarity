import requests
from common.config import UserConfig
from common.measure import measure_duration
from loguru import logger as log
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# uses Google's official Translate API (v2) to send translations.
# requires you to set up a GCP project, enable the Translate API service and obtain
# an API key to use.
#
# this talks to the REST endpoint with requests rather than googleapiclient. the
# client library's httplib2 transport keeps one TLS connection open indefinitely and
# does not retry SSL errors by default, so when Google (or a router/NAT/antivirus in
# between) drops an idle connection, the next request fails with
# "EOF occurred in violation of protocol". requests/urllib3 discards dead pooled
# connections and the retry policy below reconnects on transient drops.
class GoogleTranslate:
    _URL = "https://translation.googleapis.com/language/translate/v2"
    _TIMEOUT = (5, 10)  # (connect, read) seconds

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.target = UserConfig().target_language

        retry = Retry(
            total=2,
            connect=2,
            read=2,
            other=2,  # SSL errors (e.g. SSLEOFError) are counted here
            status=2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"POST"}),
            backoff_factor=0.3,
            respect_retry_after_header=False,  # don't stall the game thread on a long Retry-After
        )
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            response = self.session.post(
                self._URL,
                params={"key": self.api_key},
                json={"q": text, "source": "ja", "target": self.target, "format": "text"},
                timeout=self._TIMEOUT,
            )

            if not response.ok:
                # Google returns {"error": {"message": ...}} for bad keys, quota, etc.
                try:
                    message = response.json()["error"]["message"]
                except Exception:
                    message = response.text[:200]
                log.error(f"Error during request: HTTP {response.status_code}: {message}")
                return []

            return [result["translatedText"] for result in response.json()["data"]["translations"]]
        except Exception as e:
            log.error(f"Error during request: {type(e).__name__}: {e}")
            return []
