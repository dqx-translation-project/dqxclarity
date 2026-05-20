using Avalonia.Media.Imaging;
using HtmlAgilityPack;

namespace DqxClarity.Launcher.Services;

public record BannerItem(string ImageUrl, string LinkUrl);

public class BannerService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private const string BannerPageUrl = "https://dqx-translation-project.github.io/rotation-banner/";

    public async Task<List<BannerItem>> GetAllAsync()
    {
        try
        {
            var html    = await _http.GetStringAsync(BannerPageUrl);
            var doc     = new HtmlDocument();
            doc.LoadHtml(html);

            var anchors = doc.DocumentNode.SelectNodes("//a[img]");
            if (anchors == null) return [];

            var result = new List<BannerItem>();
            foreach (var anchor in anchors)
            {
                var img  = anchor.SelectSingleNode("img");
                var src  = img?.GetAttributeValue("src", "") ?? "";
                var href = anchor.GetAttributeValue("href", "");

                if (string.IsNullOrEmpty(src)) continue;

                if (!src.StartsWith("http"))
                    src = new Uri(new Uri(BannerPageUrl), src).ToString();

                result.Add(new BannerItem(src, href));
            }
            return result;
        }
        catch
        {
            return [];
        }
    }

    public async Task<Bitmap?> LoadImageAsync(string url)
    {
        try
        {
            var bytes = await _http.GetByteArrayAsync(url);
            using var ms = new MemoryStream(bytes);
            return new Bitmap(ms);
        }
        catch
        {
            return null;
        }
    }
}
