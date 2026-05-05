from common.config import UserConfig
from common.measure import measure_duration
from loguru import logger as log


_SYSTEM_PROMPT = (
    "You are an expert translator and cultural localization specialist with deep knowledge of "
    "video game localization. Translate the following Dragon Quest X dialogue from Japanese to "
    "English. Preserve the original tone, humor, personality, and emotional nuances. Adapt "
    "idioms and cultural references to resonate naturally with English speakers while maintaining "
    "the fantasy RPG context. Maintain consistency in character voices and DQX-specific "
    "terminology. Return only the translated text with no explanation or surrounding quotes."
)


class ChatGPTTranslate:
    def __init__(self, api_key: str) -> None:
        from openai import OpenAI

        cfg = UserConfig()
        self.model = cfg.chatgpt_model
        self.client = OpenAI(api_key=api_key)

    @measure_duration
    def translate(self, text: list[str]) -> list[str]:
        try:
            results = []
            for phrase in text:
                completion = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": phrase},
                    ],
                    temperature=0.1,
                )
                translated = (completion.choices[0].message.content or "").strip().strip('"')
                results.append(translated)
            return results
        except Exception as e:
            log.error(f"Error during request: {e}")
            return []
