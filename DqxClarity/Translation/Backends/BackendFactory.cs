using DqxClarity.Models;

namespace DqxClarity.Translation.Backends;

// Picks the right translation backend based on TranslationConfig.TranslateService.
// Unknown / unimplemented / unset services fall back to the None backend (no machine translation).
public static class BackendFactory
{
    public static ITranslationBackend Create(TranslationConfig config) =>
        (config.TranslateService ?? "none").ToLowerInvariant() switch
        {
            "deepl"             => new DeepLBackend(config.TranslateKey),
            "google"            => new GoogleBackend(config.TranslateKey),
            "chatgpt"           => new ChatGPTBackend(config.TranslateKey, config.ChatGptModel),
            "ollama"            => new OllamaBackend(config.OllamaUrl, config.OllamaModel),
            "yandex"            => new YandexBackend(),
            "libretranslate"    => new LibreTranslateBackend(config.LibreTranslateUrl, config.TranslateKey),
            "googletranslatepa" => new GoogleTranslatePaBackend(),
            "googlefree"        => new GoogleFreeBackend(),
            "echo"              => new EchoBackend(),
            "none"              => new NoneBackend(),
            _                   => new NoneBackend(),
        };
}
