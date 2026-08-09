using System.Text;

namespace DqxClarity.Translation;

// Greedy word-wrap with paragraph preservation and optional line truncation.
//   - split on \n; each paragraph is wrapped independently and rejoined with \n
//   - max_lines: if wrapped text exceeds the limit, truncate and append " [...]"
//   - words longer than `width` are broken (break_long_words=True semantics)
internal static class TextWrapping
{
    public static string Fill(string text, int width, int? maxLines = null)
    {
        if (width <= 0) return text;

        var allLines = new List<string>();
        foreach (var paragraph in text.Split('\n'))
        {
            if (paragraph.Length == 0)
            {
                allLines.Add("");
                continue;
            }
            WrapParagraph(paragraph, width, allLines);
        }

        if (maxLines.HasValue && allLines.Count > maxLines.Value)
        {
            allLines = allLines.Take(maxLines.Value).ToList();
            // append " [...]" to the last kept line
            if (allLines.Count > 0)
            {
                var last = allLines[^1];
                var placeholder = " [...]";
                if (last.Length + placeholder.Length > width)
                {
                    var trimTo = Math.Max(0, width - placeholder.Length);
                    last = last[..Math.Min(last.Length, trimTo)].TrimEnd();
                }
                allLines[^1] = last + placeholder;
            }
        }

        return string.Join('\n', allLines);
    }

    private static void WrapParagraph(string paragraph, int width, List<string> outLines)
    {
        var words = paragraph.Split(' ');
        var line = new StringBuilder();

        foreach (var word in words)
        {
            if (line.Length == 0)
            {
                // first word on a line — break it if it's longer than width
                EmitWord(word, width, line, outLines);
            }
            else if (line.Length + 1 + word.Length <= width)
            {
                line.Append(' ').Append(word);
            }
            else
            {
                outLines.Add(line.ToString());
                line.Clear();
                EmitWord(word, width, line, outLines);
            }
        }

        if (line.Length > 0)
            outLines.Add(line.ToString());
    }

    private static void EmitWord(string word, int width, StringBuilder line, List<string> outLines)
    {
        // break_long_words=True semantics: chop the word into chunks of `width` chars
        if (word.Length <= width)
        {
            line.Append(word);
            return;
        }
        for (var i = 0; i < word.Length; i += width)
        {
            var chunkLen = Math.Min(width, word.Length - i);
            var chunk = word.Substring(i, chunkLen);
            if (chunk.Length == width)
            {
                outLines.Add(chunk);
            }
            else
            {
                line.Append(chunk);
            }
        }
    }

    // Injects <br> as a separate line every 3 wrapped lines so dialog windows page correctly.
    // Drops trailing empty lines.
    public static string InjectBrEvery3Lines(string text)
    {
        var lines = text.Split('\n').ToList();
        // inserts at positions 3, 7, 11, ... (every 4 with offset 3).
        // when the index is out of range, falls back to joining non-empty lines.
        var insertAt = new List<int> { };
        for (var i = 3; i < 500; i += 4) insertAt.Add(i);

        try
        {
            foreach (var idx in insertAt)
            {
                // out-of-bounds triggers the fallback path below
                if (idx >= lines.Count) throw new IndexOutOfRangeException();
                lines.Insert(idx, "<br>");
            }
        }
        catch (IndexOutOfRangeException)
        {
            // fall back: strip empty lines and rejoin
            lines = lines.Where(s => !string.IsNullOrEmpty(s)).ToList();
            return string.Join('\n', lines);
        }

        return string.Join('\n', lines);
    }
}
