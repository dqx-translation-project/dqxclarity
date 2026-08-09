using DqxClarity.Models;

namespace DqxClarity.Translation.Backends;

// Picks the right translation backend based on TranslationConfig.TranslateService.
// Unknown / unimplemented services fall back to the GoogleFree backend (no api key required).
public static class BackendFactory
{
    public static ITranslationBackend Create(TranslationConfig config) =>
        (config.TranslateService ?? "googlefree").ToLowerInvariant() switch
        {
            "deepl"             => new DeepLBackend(config.TranslateKey),
            "google"            => new GoogleBackend(config.TranslateKey),
            "chatgpt"           => new ChatGPTBackend(config.TranslateKey, config.ChatGptModel),
            "ollama"            => new OllamaBackend(config.OllamaUrl, config.OllamaModel),
            "yandex"            => new YandexBackend(),
            "libretranslate"    => new LibreTranslateBackend(config.LibreTranslateUrl, config.TranslateKey),
            "googletranslatepa" => new GoogleTranslatePaBackend(),
            "googlefree"        => new GoogleFreeBackend(),
            "echo" or "none"    => new EchoBackend(),
            _                   => new GoogleFreeBackend(),
        };
}
