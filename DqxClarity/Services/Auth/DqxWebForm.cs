using System.Net;
using HtmlAgilityPack;

namespace DqxClarity.Services.Auth;

internal class DqxWebForm
{
    public HttpMethod Method { get; private set; } = HttpMethod.Post;
    public string Action { get; private set; } = "";
    public Dictionary<string, string> Fields { get; private set; } = new();

    public static DqxWebForm Parse(HtmlNode form, Uri baseUri)
    {
        var rawAction = WebUtility.HtmlDecode(form.GetAttributeValue("action", ""));
        var action = new Uri(baseUri, rawAction);

        var method = form.GetAttributeValue("method", "POST").ToUpperInvariant() switch
        {
            "GET" => HttpMethod.Get,
            _ => HttpMethod.Post,
        };

        var fields = form.Descendants("input")
            .Where(n => !string.IsNullOrEmpty(n.GetAttributeValue("name", "")))
            .GroupBy(n => n.GetAttributeValue("name", ""))
            .ToDictionary(
                g => g.Key,
                g => WebUtility.HtmlDecode(g.Last().GetAttributeValue("value", "")));

        return new DqxWebForm { Method = method, Action = action.ToString(), Fields = fields };
    }
}
