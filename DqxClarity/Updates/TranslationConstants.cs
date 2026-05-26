namespace DqxClarity.Updates;

internal static class TranslationConstants
{
    public const string CustomTranslationsZipUrl =
        "https://github.com/dqx-translation-project/dqx-custom-translations/archive/refs/heads/main.zip";

    public const string MonstersJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/subPackage02Client.win32.json";
    public const string NpcJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/smldt_msg_pkg_NPC_DB.win32.json";
    public const string ItemsJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/subPackage05Client.json";
    public const string KeyItemsJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/subPackage41Client.win32.json";
    public const string QuestsJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/eventTextSysQuestaClient.json";
    public const string CutsceneJsonUrl =
        "https://raw.githubusercontent.com/dqx-translation-project/dqx_translations/main/json/_lang/en/eventTextSysEventaClient.win32.json";

    public const string CommunityStringApiUrl = "https://community-string-api.ethene.wiki";

    public static readonly (string Url, string Name)[] TranslationFiles =
    {
        (MonstersJsonUrl, "monsters"),
        (NpcJsonUrl,      "npcs"),
        (ItemsJsonUrl,    "items"),
        (KeyItemsJsonUrl, "key_items"),
        (QuestsJsonUrl,   "quests"),
        (CutsceneJsonUrl, "story_names"),
    };
}
