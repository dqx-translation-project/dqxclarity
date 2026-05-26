namespace DqxClarity.Translation;

// Game-specific placeholder tags (<pc>, <%sM_NAME>, ...) are temporarily swapped
// for short ascii sigils (<&13_aaaaaae>, ...) before being sent to a translation
// service, then swapped back afterwards. Sigils survive most translators
// unchanged. The swap-back step also accepts the same sigil at multiple lengths
// (off-by-one variants where a translator added or dropped one of the trailing
// 'a' characters), which is intentional defensive coding.
internal static class PlaceholderTags
{
    // Forward swap: original tag -> sigil.
    private static readonly (string Tag, string Sigil)[] Forward =
    {
        ("<pc_hiryu>",          "<&13_aaaaaaa>"),
        ("<cs_pchero_hiryu>",   "<&13_aaaaaab>"),
        ("<cs_pchero_race>",    "<&8_aaa>"),
        ("<cs_pchero>",         "<&13_aaaaaac>"),
        ("<kyodai_rel1>",       "<&7_aa>"),
        ("<kyodai_rel2>",       "<&7_ab>"),
        ("<kyodai_rel3>",       "<&7_ac>"),
        ("<pc_hometown>",       "<&8_aab>"),
        ("<pc_race>",           "<&8_aac>"),
        ("<%sM_real_race>",     "<&8_aad>"),
        ("<pc_rel1>",           "<&7_ad>"),
        ("<pc_rel2>",           "<&7_ae>"),
        ("<pc_rel3>",           "<&7_af>"),
        ("<kyodai>",            "<&13_aaaaaad>"),
        ("<pc>",                "<&13_aaaaaae>"),
        ("<client_pcname>",     "<&13_aaaaaaf>"),
        ("<heart>",             "<&2a>"),
        ("<diamond>",           "<&2b>"),
        ("<spade>",             "<&2c>"),
        ("<clover>",            "<&2d>"),
        ("<r_triangle>",        "<&2e>"),
        ("<l_triangle>",        "<&2f>"),
        ("<half_star>",         "<&2g>"),
        ("<null_star>",         "<&2h>"),
        ("<npc>",               "<&13_aaaaaag>"),
        ("<pc_syokugyo>",       "<&13_aaaaaah>"),
        ("<pc_original>",       "<&13_aaaaaai>"),
        ("<log_pc>",            "<&13_aaaaaaj>"),
        ("<%sM_NAME>",          "<&13_aaaaaak>"),
        ("<%sM_BEFORE_NAME>",   "<&13_aaaaaal>"),
        ("<%sM_OWNER_OTHER>",   "<&13_aaaaaam>"),
        ("<%sM_OWNER>",         "<&13_aaaaaan>"),
        ("<%sM_SAMA>",          "<&6_a>"),
        ("<1st_title>",         "<&20_aaaaaaaaaaaaaa>"),
        ("<2nd_title>",         "<&20_aaaaaaaaaaaaab>"),
        ("<3rd_title>",         "<&20_aaaaaaaaaaaaac>"),
        ("<4th_title>",         "<&20_aaaaaaaaaaaaad>"),
        ("<5th_title>",         "<&20_aaaaaaaaaaaaae>"),
        ("<6th_title>",         "<&20_aaaaaaaaaaaaaf>"),
        ("<7th_title>",         "<&20_aaaaaaaaaaaaag>"),
    };

    // Backward swap: each tag has up to 3 length variants of its sigil to absorb translator drift.
    // Tuple format: (sigil_variant, original_tag).
    private static readonly (string Sigil, string Tag)[] Backward =
    {
        ("<&13_aaaaaaaa>",  "<pc_hiryu>"),
        ("<&13_aaaaaaa>",   "<pc_hiryu>"),
        ("<&13_aaaaaa>",    "<pc_hiryu>"),
        ("<&13_aaaaaaab>",  "<cs_pchero_hiryu>"),
        ("<&13_aaaaaab>",   "<cs_pchero_hiryu>"),
        ("<&13_aaaaab>",    "<cs_pchero_hiryu>"),
        ("<&8_aaa>",        "<cs_pchero_race>"),
        ("<&13_aaaaaaac>",  "<cs_pchero>"),
        ("<&13_aaaaaac>",   "<cs_pchero>"),
        ("<&13_aaaaac>",    "<cs_pchero>"),
        ("<&7_aa>",         "<kyodai_rel1>"),
        ("<&7_ab>",         "<kyodai_rel2>"),
        ("<&7_ac>",         "<kyodai_rel3>"),
        ("<&8_aab>",        "<pc_hometown>"),
        ("<&8_aac>",        "<pc_race>"),
        ("<&8_aad>",        "<%sM_real_race>"),
        ("<&7_ad>",         "<pc_rel1>"),
        ("<&7_ae>",         "<pc_rel2>"),
        ("<&7_af>",         "<pc_rel3>"),
        ("<&13_aaaaaaad>",  "<kyodai>"),
        ("<&13_aaaaaad>",   "<kyodai>"),
        ("<&13_aaaaad>",    "<kyodai>"),
        ("<&13_aaaaaaae>",  "<pc>"),
        ("<&13_aaaaaae>",   "<pc>"),
        ("<&13_aaaaae>",    "<pc>"),
        ("<&13_aaaaaaaf>",  "<client_pcname>"),
        ("<&13_aaaaaaf>",   "<client_pcname>"),
        ("<&13_aaaaaf>",    "<client_pcname>"),
        ("<&2a>",           "<heart>"),
        ("<&2b>",           "<diamond>"),
        ("<&2c>",           "<spade>"),
        ("<&2d>",           "<clover>"),
        ("<&2e>",           "<r_triangle>"),
        ("<&2f>",           "<l_triangle>"),
        ("<&2g>",           "<half_star>"),
        ("<&2h>",           "<null_star>"),
        ("<&13_aaaaaaag>",  "<npc>"),
        ("<&13_aaaaaag>",   "<npc>"),
        ("<&13_aaaaag>",    "<npc>"),
        ("<&13_aaaaaaah>",  "<pc_syokugyo>"),
        ("<&13_aaaaaah>",   "<pc_syokugyo>"),
        ("<&13_aaaaah>",    "<pc_syokugyo>"),
        ("<&13_aaaaaaai>",  "<pc_original>"),
        ("<&13_aaaaaai>",   "<pc_original>"),
        ("<&13_aaaaai>",    "<pc_original>"),
        ("<&13_aaaaaaaj>",  "<log_pc>"),
        ("<&13_aaaaaaj>",   "<log_pc>"),
        ("<&13_aaaaaj>",    "<log_pc>"),
        ("<&13_aaaaaaak>",  "<%sM_NAME>"),
        ("<&13_aaaaaak>",   "<%sM_NAME>"),
        ("<&13_aaaaak>",    "<%sM_NAME>"),
        ("<&13_aaaaaaal>",  "<%sM_BEFORE_NAME>"),
        ("<&13_aaaaaal>",   "<%sM_BEFORE_NAME>"),
        ("<&13_aaaaal>",    "<%sM_BEFORE_NAME>"),
        ("<&13_aaaaaaam>",  "<%sM_OWNER_OTHER>"),
        ("<&13_aaaaaam>",   "<%sM_OWNER_OTHER>"),
        ("<&13_aaaaam>",    "<%sM_OWNER_OTHER>"),
        ("<&13_aaaaaaan>",  "<%sM_OWNER>"),
        ("<&13_aaaaaan>",   "<%sM_OWNER>"),
        ("<&13_aaaaan>",    "<%sM_OWNER>"),
        ("<&6_a>",          "<%sM_SAMA>"),
        ("<&20_aaaaaaaaaaaaaaa>",  "<1st_title>"),
        ("<&20_aaaaaaaaaaaaaa>",   "<1st_title>"),
        ("<&20_aaaaaaaaaaaaa>",    "<1st_title>"),
        ("<&20_aaaaaaaaaaaaaab>",  "<2nd_title>"),
        ("<&20_aaaaaaaaaaaaab>",   "<2nd_title>"),
        ("<&20_aaaaaaaaaaaab>",    "<2nd_title>"),
        ("<&20_aaaaaaaaaaaaaac>",  "<3rd_title>"),
        ("<&20_aaaaaaaaaaaaac>",   "<3rd_title>"),
        ("<&20_aaaaaaaaaaaac>",    "<3rd_title>"),
        ("<&20_aaaaaaaaaaaaaad>",  "<4th_title>"),
        ("<&20_aaaaaaaaaaaaad>",   "<4th_title>"),
        ("<&20_aaaaaaaaaaaad>",    "<4th_title>"),
        ("<&20_aaaaaaaaaaaaaae>",  "<5th_title>"),
        ("<&20_aaaaaaaaaaaae>",    "<5th_title>"),
        ("<&20_aaaaaaaaaaaaae>",   "<5th_title>"),
        ("<&20_aaaaaaaaaaaaaaf>",  "<6th_title>"),
        ("<&20_aaaaaaaaaaaaaf>",   "<6th_title>"),
        ("<&20_aaaaaaaaaaaaf>",    "<6th_title>"),
        ("<&20_aaaaaaaaaaaaaag>",  "<7th_title>"),
        ("<&20_aaaaaaaaaaaaag>",   "<7th_title>"),
        ("<&20_aaaaaaaaaaaag>",    "<7th_title>"),
    };

    public static string Swap(string text)
    {
        foreach (var (tag, sigil) in Forward)
            text = text.Replace(tag, sigil);
        return text;
    }

    public static string SwapBack(string text)
    {
        foreach (var (sigil, tag) in Backward)
            text = text.Replace(sigil, tag);
        return text;
    }
}
