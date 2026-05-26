using HtmlAgilityPack;

namespace DqxClarity.Services.Auth;

internal class DqxLoginResponse
{
    private readonly HtmlDocument _doc;
    private readonly Uri _requestUri;

    private DqxLoginResponse(HtmlDocument doc, Uri requestUri)
    {
        _doc = doc;
        _requestUri = requestUri;
    }

    public static async Task<DqxLoginResponse> ParseAsync(HttpResponseMessage response)
    {
        var doc = new HtmlDocument();
        doc.LoadHtml(await response.Content.ReadAsStringAsync());
        return new DqxLoginResponse(doc, response.RequestMessage!.RequestUri!);
    }

    public static DqxLoginResponse Parse(string body, Uri requestUri)
    {
        var doc = new HtmlDocument();
        doc.LoadHtml(body);
        return new DqxLoginResponse(doc, requestUri);
    }


    private HtmlNode? SqexAuthNode => _doc.DocumentNode.SelectSingleNode("//x-sqexauth");

    public string? SessionId => SqexAuthNode?.GetAttributeValue("sid", null);
    public string? Token => SqexAuthNode?.GetAttributeValue("id", null);
    public string? Code => SqexAuthNode?.GetAttributeValue("code", null);
    public string? Mode => SqexAuthNode?.GetAttributeValue("mode", null);

    public string? ErrorMessage
    {
        get
        {
            var msg = SqexAuthNode?.GetAttributeValue("message", null);
            return string.IsNullOrEmpty(msg) ? null : msg;
        }
    }

    public DqxWebForm? Form
    {
        get
        {
            var form = _doc.DocumentNode.SelectSingleNode("//form[@name='mainForm']");
            return form is null ? null : DqxWebForm.Parse(form, _requestUri);
        }
    }

    public bool IsOtpForm =>
        _doc.DocumentNode.SelectSingleNode("//input[@name='otppw']") is not null;
}
