using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace DqxClarity.Translation;

//

// Formats DQX quest reward lines (e.g. "・○○薬草　　 5こ") into the western
// quest-window layout: "・<translated item>     (qty)". Items are looked up in
// m00 'custom_quest_rewards', 'items', 'key_items'. Lines without a match pass
// through unchanged; experience-point bullets get a hard-coded translation.
//
// `quantity` rules:
//   - line ends with "こ"  -> "(<digit>)", normalised NFKC and stripped of spaces
//   - line ends with "他"  -> "(1)" unless one of two bad-string markers is present
public sealed class QuestRewardFormatter
{
    private readonly IReadOnlyDictionary<string, string> _rewards;

    private static readonly string[] BadStrings = { "必殺技を覚える", "入れられるよう" };

    public QuestRewardFormatter(IReadOnlyDictionary<string, string> rewards)
    {
        _rewards = rewards;
    }

    public string Format(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;

        var lineCount = text.Count(c => c == '\n');
        var sanitized = text
            .Replace("男は ", "")
            .Replace("女は ", "")
            .Replace("男は　", "")
            .Replace("女は　", "");

        var final = new StringBuilder();
        foreach (var item in sanitized.Split('\n'))
        {
            var quantity = "";
            var noBullet = Regex.Replace(item, @"^・", "");
            var points = noBullet.Length >= 18 ? noBullet.Substring(6, 12) : "";

            if (noBullet.EndsWith("こ", StringComparison.Ordinal) && noBullet.Length >= 3)
            {
                var sub = noBullet.Substring(noBullet.Length - 3, 2);
                quantity = "(" + sub.Normalize(NormalizationForm.FormKC) + ")";
                quantity = quantity.Replace(" ", "");
            }
            if (noBullet.EndsWith("他", StringComparison.Ordinal))
            {
                quantity = BadStrings.Any(b => noBullet.Contains(b, StringComparison.Ordinal)) ? "" : "(1)";
            }
            noBullet = Regex.Replace(noBullet, "　　.*", "");

            if (_rewards.TryGetValue(noBullet, out var value) && !string.IsNullOrEmpty(value))
            {
                var valueLength = value.Length;
                var quantLength = quantity.Length;
                var byteCount = Encoding.UTF8.GetByteCount(value);
                var numSpaces = Math.Max(0, 31 - valueLength - quantLength - ((byteCount - valueLength) / 2));
                var spaces = new string(' ', numSpaces);

                if (item.Contains("・", StringComparison.Ordinal))
                {
                    if (lineCount == 0) return "・" + value + spaces + quantity;
                    final.Append("・").Append(value).Append(spaces).Append(quantity).Append('\n');
                }
                else
                {
                    if (lineCount == 0) return value + spaces + quantity;
                    final.Append(value).Append(spaces).Append(quantity).Append('\n');
                }
            }
            else
            {
                if (lineCount == 0)
                {
                    if (item.Contains("討伐ポイント", StringComparison.Ordinal))
                        return "・Experience Points" + points;
                    return text;
                }
                final.Append(item).Append('\n');
            }
        }

        return final.ToString().TrimEnd();
    }
}
