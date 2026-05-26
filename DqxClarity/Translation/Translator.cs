using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using DqxClarity.Data;

namespace DqxClarity.Translation;

// Translation pipeline (must run in this order):
//
//   1. <br> -> full-width space (we manage line endings ourselves)
//   2. strip alignment tags (<center>, <left>, <right>)
//   3. collapse ellipsis runs (16, 15, 14 ... 2 dots) to a single ellipsis
//   4. drop ornamentals (「 ～ ♪)
//   5. fold "。" -> "."  (and "…。" -> ".")
//   6. drop leading full-width space on new lines
//   7. strip honorifics that follow a name tag
//   8. protect color tags: <color_X> -> <&color_X>
//   9. swap placeholder tags (PlaceholderTags.Swap)
//  10. glossary substitution (GlossaryCache.Apply)
//  11. split on `<[^%&]*?>` tags; track per-fragment is_list / prepend_nl / append_nl
//  12. send fragment text list to backend
//  13. for each translated fragment, sanitize spaces, normalize NFKD, wrap, swap-back,
//      restore color tags, optionally inject <br>, optionally re-prepend/append \n,
//      and handle <voice> end-of-string rule
public sealed class Translator
{
    private static readonly Regex JpRegex = new(@"\p{IsHiragana}|\p{IsKatakana}|\p{IsCJKUnifiedIdeographs}", RegexOptions.Compiled);
    private static readonly Regex ColorOpen = new(@"<color_(\w+)>", RegexOptions.Compiled);
    private static readonly Regex ColorOpenProtected = new(@"<&color_(\w+)>", RegexOptions.Compiled);
    private static readonly Regex ColorBareProtected = new(@"(?<!<)&color_(\w+)>", RegexOptions.Compiled);
    private static readonly Regex TagRe = new(@"(<[^%&]*?>)", RegexOptions.Compiled);
    private static readonly Regex SelectRe = new(@"<select.*?>", RegexOptions.Compiled);
    private static readonly Regex VoiceRe = new(@"<voice.*?>", RegexOptions.Compiled);

    private static readonly string[] Alignments = { "<center>", "<right>", "<left>" };
    private static readonly string[] Ellipses =
    {
        "…………………………………………", "………………………………………", "……………………………………",
        "…………………………………", "………………………………",   "……………………………",
        "…………………………",   "………………………",     "……………………",
        "…………………",     "………………",         "……………",
        "…………",         "………",              "……",
    };
    private static readonly string[] Oddities = { "「", "～", "♪" };
    private static readonly string[] NameTags = { "<pc>", "<cs_pchero>", "<kyodai>" };
    private static readonly string[] Honorifics = { "さま", "君", "どの", "ちゃん", "くん", "様", "さーん", "殿", "さん" };

    private readonly ITranslationBackend _backend;
    private readonly GlossaryCache _glossary;

    public Translator(ITranslationBackend backend, GlossaryCache glossary)
    {
        _backend = backend;
        _glossary = glossary;
    }

    public static bool IsTextJapanese(string text)
    {
        var sanitized = Regex.Replace(text, "<.+?>", "");
        return JpRegex.IsMatch(sanitized);
    }

    private static string NormalizeText(string text)
    {
        var normalized = text.Normalize(NormalizationForm.FormKD);
        var sb = new StringBuilder(normalized.Length);
        foreach (var c in normalized)
            if (c <= 0x7F) sb.Append(c);
        return sb.ToString();
    }

    public string Translate(string text, int wrapWidth, int? maxLines = null, bool addBrs = true)
    {
        // Stage 1-9: prepare the source text.
        var output = text.Replace("<br>", "　");

        foreach (var a in Alignments) output = output.Replace(a, "");
        foreach (var e in Ellipses) output = output.Replace(e, "…");
        foreach (var o in Oddities) output = output.Replace(o, "");

        output = output.Replace("…。", ".");
        output = output.Replace("。", ".");
        output = output.Replace("\n　", "\n");

        foreach (var tag in NameTags)
            foreach (var h in Honorifics)
                output = output.Replace($"{tag}{h}", tag);

        output = ColorOpen.Replace(output, "<&color_$1>");
        output = PlaceholderTags.Swap(output);
        output = _glossary.Apply(output);

        var pristine = output;

        // Stage 11: split on tags; preserve captured tag separators.
        var splits = TagRe.Split(output).Where(s => s.Length > 0).ToList();

        var strAttrs = new List<FragmentAttr>();
        var fragIndices = new List<int>();  // position in splits[] for is_list lookback

        for (var i = 0; i < splits.Count; i++)
        {
            var s = splits[i];
            if (TagRe.IsMatch(s)) continue;

            if (s == "\n") continue;

            var idx = strAttrs.Count;
            pristine = pristine.Replace(s, $"<replace_me_index_{idx}>");

            if (s.StartsWith('\n'))
            {
                var lookback = i - 1;
                if (lookback >= 0 && SelectRe.IsMatch(splits[lookback]))
                {
                    strAttrs.Add(new FragmentAttr
                    {
                        Text = s,
                        IsList = true,
                        PrependNewline = false,
                        AppendNewline = false,
                    });
                    fragIndices.Add(i);
                    continue;
                }
            }

            var appendNl = s.EndsWith('\n');
            var prependNl = s.StartsWith('\n');
            var sansNl = s.Replace("\n", "").Trim();

            strAttrs.Add(new FragmentAttr
            {
                Text = sansNl,
                IsList = false,
                PrependNewline = prependNl,
                AppendNewline = appendNl,
            });
            fragIndices.Add(i);
        }

        // Stage 12: build the to-translate list, expanding list fragments line-by-line.
        var toTranslate = new List<string>();
        foreach (var a in strAttrs)
        {
            if (!a.IsList)
                toTranslate.Add(a.Text);
            else
                foreach (var line in a.Text.Split('\n'))
                    if (!string.IsNullOrEmpty(line))
                        toTranslate.Add(line);
        }

        var translated = _backend.Translate(toTranslate);
        if (translated == null || translated.Count != toTranslate.Count)
            return "";

        // Stage 12b: redistribute translated entries back to attrs.
        for (var c = 0; c < translated.Count; c++)
        {
            if (c >= strAttrs.Count) break;
            if (!strAttrs[c].IsList)
            {
                strAttrs[c].Text = translated[c];
            }
            else
            {
                // list fragments collect the remainder of translated[].
                var joined = string.Join('\n', translated.Skip(c)) + "\n";
                strAttrs[c].Text = joined;
                break;
            }
        }

        // Stage 13: post-process each fragment back into pristine.
        for (var c = 0; c < strAttrs.Count; c++)
        {
            var attr = strAttrs[c];
            var t = attr.Text;

            t = t.Replace("　 ", " ")
                 .Replace(" 　", " ")
                 .Replace("　", " ")
                 .Replace("  ", " ")
                 .Replace("..................", "...")
                 .Replace("...............", "...")
                 .Replace("............", "...")
                 .Replace(".........", "...")
                 .Replace("......", "...")
                 .Replace("....", "...");

            t = t.Replace("’", "'");

            var updated = t.Replace("—", "--");
            updated = NormalizeText(updated);

            if (attr.IsList)
            {
                updated = PlaceholderTags.SwapBack(updated);
                updated = ColorOpenProtected.Replace(updated, "<color_$1>");
                updated = ColorBareProtected.Replace(updated, "<color_$1>");
                updated = updated.Replace("\n ", "\n");
                updated = updated.Replace("\n　", "\n");
                pristine = pristine.Replace($"<replace_me_index_{c}>", updated);
            }
            else
            {
                updated = TextWrapping.Fill(updated, wrapWidth, maxLines);
                updated = PlaceholderTags.SwapBack(updated);
                updated = ColorOpenProtected.Replace(updated, "<color_$1>");
                updated = ColorBareProtected.Replace(updated, "<color_$1>");

                if (addBrs)
                    updated = TextWrapping.InjectBrEvery3Lines(updated);

                if (attr.PrependNewline) updated = "\n" + updated;
                if (attr.AppendNewline) updated = updated + "\n";

                // Voice tag rule: if pristine_str matches <voice...> (but not the Asfeld
                // IEV_GS variant), and the previous tag in pristine_str was a <voice...>,
                // ensure this fragment ends with <br>\n.
                if (VoiceRe.IsMatch(pristine) && !pristine.Contains("IEV_GS"))
                {
                    var tagList = TagRe.Matches(pristine).Select(m => m.Value).ToList();
                    var curIdx = tagList.IndexOf($"<replace_me_index_{c}>");
                    if (curIdx >= 0 && curIdx != tagList.Count - 1)
                    {
                        var lookback = curIdx - 1;
                        if (lookback >= 0 && VoiceRe.IsMatch(tagList[lookback]))
                            if (!updated.EndsWith("<br>"))
                                updated += "<br>\n";
                    }
                }

                pristine = pristine.Replace($"<replace_me_index_{c}>", updated);
            }
        }

        return pristine;
    }

    private sealed class FragmentAttr
    {
        public string Text { get; set; } = "";
        public bool IsList { get; set; }
        public bool PrependNewline { get; set; }
        public bool AppendNewline { get; set; }
    }
}
