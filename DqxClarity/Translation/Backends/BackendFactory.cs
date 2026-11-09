using DqxClarity.Models;

namespace DqxClarity.Translation.Backends;

// Picks the right translation backend based on TranslationConfig.TranslateService.
// Unknown / unimplemented / unset services fall back to the None backend (no machine translation).
public static class BackendFactory
{
    // Target language comes from the primary language pack (TranslationConfig.TargetLanguage
    // / TargetLanguageName); English when none is set.
    public static ITranslationBackend Create(TranslationConfig config)
    {
        var lang = string.IsNullOrWhiteSpace(config.TargetLanguage) ? "en" : config.TargetLanguage.Trim();
        var langName = string.IsNullOrWhiteSpace(config.TargetLanguageName) ? "English" : config.TargetLanguageName.Trim();

        return (config.TranslateService ?? "none").ToLowerInvariant() switch
        {
            "deepl"             => new DeepLBackend(config.TranslateKey, lang),
            "google"            => new GoogleBackend(config.TranslateKey, lang),
            "chatgpt"           => new ChatGPTBackend(config.TranslateKey, config.ChatGptModel, langName),
            "ollama"            => new OllamaBackend(config.OllamaUrl, config.OllamaModel, langName),
            "yandex"            => new YandexBackend(lang),
            "libretranslate"    => new LibreTranslateBackend(config.LibreTranslateUrl, config.TranslateKey, lang),
            "googletranslatepa" => new GoogleTranslatePaBackend(lang),
            "googlefree"        => new GoogleFreeBackend(lang),
            "echo"              => new EchoBackend(),
            "none"              => new NoneBackend(),
            _                   => new NoneBackend(),
        };
    }
}
