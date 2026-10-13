using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Velauth.Scan.Model;

namespace Velauth.Scan.Report;

public static class ReportWriter
{
    public static void WriteJson(string path, ScanResult result)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(result, JsonOptions.Indented), new UTF8Encoding(false));
    }

    public static void WriteHtml(string path, ScanResult result, string? company, string? logoPath)
    {
        File.WriteAllText(path, RenderHtml(result, company, LoadLogo(logoPath)), new UTF8Encoding(false));
    }

    internal static string RenderHtml(ScanResult result, string? company = null, string? logoDataUri = null)
    {
        var output = new StringBuilder(32_768);
        output.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
            .Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\">")
            .Append("<title>Velauth AD Helpdesk Exposure Scan</title><style>")
            .Append("body{font:14px/1.5 system-ui,sans-serif;color:#15152b;background:#fff;margin:0}main{max-width:980px;margin:auto;padding:36px}")
            .Append("header{display:flex;justify-content:space-between;align-items:center;border-bottom:4px solid #302c73;padding-bottom:18px}.logo{max-width:180px;max-height:64px}")
            .Append("h1,h2,h3{color:#242057}h1{margin:.2rem 0}.summary{display:grid;grid-template-columns:1fr 2fr;gap:28px;margin:30px 0}.grade{font-size:64px;font-weight:800;color:#302c73}")
            .Append(".headline{background:#eeedfb;border:2px solid #302c73;border-radius:10px;padding:22px;margin:20px 0 30px}.headline strong{display:block;font-size:28px;line-height:1.25;color:#242057}.headline .sub{font-size:17px;margin-top:8px}")
            .Append(".card,.finding{border:1px solid #d9d8e8;border-radius:8px;padding:18px;margin:18px 0}.fail{border-left:7px solid #a92c3a}.pass{border-left:7px solid #27734d}.notvisible{border-left:7px solid #766f83}")
            .Append("table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #ddd;padding:9px}code{white-space:pre-wrap;overflow-wrap:anywhere}.accounts{columns:2}footer{border-top:1px solid #bbb;margin-top:36px;padding-top:18px;font-size:12px}")
            .Append("@media print{main{max-width:none;padding:0}.page-one{break-after:page}.finding{break-inside:avoid}a{color:inherit}.accounts{columns:3}}")
            .Append("</style></head><body><main>");

        output.Append("<section class=\"page-one\"><header><div><div>Velauth</div><h1>AD Helpdesk Exposure Scan</h1><div>")
            .Append(E(result.DomainName)).Append("</div></div>");
        if (!string.IsNullOrEmpty(logoDataUri))
            output.Append("<img class=\"logo\" alt=\"Company logo\" src=\"").Append(E(logoDataUri)).Append("\">");
        else if (!string.IsNullOrWhiteSpace(company))
            output.Append("<strong>").Append(E(company)).Append("</strong>");
        output.Append("</header><div class=\"summary\"><div><div class=\"grade\">").Append(E(result.Grade)).Append("</div><div>Grade</div></div><div><h2>Coverage</h2><p>")
            .Append(result.Coverage.Completed).Append(" of ").Append(result.Coverage.Total).Append(" checks ran (")
            .Append(result.Coverage.Percent).Append("%). Not visible checks do not count as passes and do not lower the grade.</p></div></div>");

        var resetFinding = result.Findings.FirstOrDefault(finding => finding.Id == 1);
        var privilegedFinding = result.Findings.FirstOrDefault(finding => finding.Id == 2);
        output.Append("<div class=\"headline\">");
        if (resetFinding?.Status == CheckStatus.NotVisible || result.BlastRadius is null)
        {
            output.Append("<strong>Not visible to this scan</strong><div class=\"sub\">")
                .Append(E(resetFinding?.NotVisibleReason ?? "The password reset blast radius could not be calculated."))
                .Append("</div>");
        }
        else
        {
            var blast = result.BlastRadius;
            output.Append("<strong>").Append(blast.ResettableEnabledUsers).Append(" of ").Append(blast.EnabledUsers)
                .Append(" enabled accounts could be taken over by one convincing phone call to your helpdesk.</strong><div class=\"sub\">Delegated to ")
                .Append(blast.DelegatedPeople).Append(blast.DelegatedPeople == 1 ? " person through " : " people through ").Append(blast.DelegatedPrincipals).Append(blast.DelegatedPrincipals == 1 ? " delegated group or account. " : " delegated groups or accounts. ");
            if (privilegedFinding?.Status == CheckStatus.NotVisible)
                output.Append("The privileged overlap is not visible to this scan.");
            else
                {
                var privilegedCount = privilegedFinding?.Count ?? 0;
                output.Append(privilegedCount).Append(privilegedCount == 1 ? " privileged account is reachable this way." : " privileged accounts are reachable this way.");
            }
            output.Append("</div>");
            if (blast.TopPrincipals.Count > 0)
            {
                output.Append("<h2>Top reset principals</h2><table><thead><tr><th>Name</th><th>Accounts reachable</th><th>People</th></tr></thead><tbody>");
                foreach (var principal in blast.TopPrincipals)
                {
                    output.Append("<tr><td>").Append(E(principal.Name)).Append("</td><td>")
                        .Append(principal.ReachableUsers).Append("</td><td>").Append(principal.Members).Append("</td></tr>");
                }
                output.Append("</tbody></table>");
            }
        }
        output.Append("</div>");

        output.Append("<h2>Top five fixes</h2><ol>");
        var failures = result.Findings.Where(finding => finding.Status == CheckStatus.Fail)
            .OrderByDescending(finding => finding.Severity)
            .ThenByDescending(finding => finding.Count ?? 0)
            .ThenBy(finding => finding.Id)
            .Take(5).ToArray();
        if (failures.Length == 0)
            output.Append("<li>No failed checks in the visible coverage.</li>");
        foreach (var finding in failures)
            output.Append("<li><strong>").Append(E(finding.Title)).Append(":</strong> ").Append(E(finding.Fix)).Append("</li>");
        output.Append("</ol><h2>Questions your insurer may ask</h2><table><thead><tr><th>Question</th><th>Answer</th></tr></thead><tbody>");
        foreach (var finding in result.Findings.Where(finding => finding.InsurerQuestion is not null))
        {
            var answer = finding.Status switch
            {
                CheckStatus.Pass => "Yes",
                CheckStatus.Fail => "No",
                _ => "Not visible to this scan",
            };
            output.Append("<tr><td>").Append(E(finding.InsurerQuestion)).Append("</td><td>").Append(answer).Append("</td></tr>");
        }
        output.Append("</tbody></table></section><section><h2>Detailed findings</h2>");

        foreach (var finding in result.Findings.OrderBy(finding => finding.Id))
        {
            var statusClass = finding.Status.ToString().ToLowerInvariant();
            output.Append("<article class=\"finding ").Append(statusClass).Append("\"><h3>")
                .Append(finding.Id).Append(". ").Append(E(finding.Title)).Append("</h3><p><strong>")
                .Append(E(finding.Status.ToString())).Append(" | ").Append(E(finding.Severity.ToString())).Append(" | ")
                .Append(E(finding.Category)).Append("</strong></p><p><strong>Why:</strong> ").Append(E(finding.Why))
                .Append("</p><p><strong>Fix:</strong> ").Append(E(finding.Fix)).Append("</p>");
            if (finding.NotVisibleReason is not null)
                output.Append("<p><strong>Not visible:</strong> ").Append(E(finding.NotVisibleReason)).Append("</p>");
            if (finding.VelauthHint is not null)
                output.Append("<p><strong>").Append(E(finding.VelauthHint)).Append("</strong></p>");
            if (finding.Details is not null)
                output.Append("<details><summary>Structured detail</summary><pre><code>")
                    .Append(E(JsonSerializer.Serialize(finding.Details, JsonOptions.Indented)))
                    .Append("</code></pre></details>");
            if (finding.Accounts.Count > 0)
            {
                output.Append("<p><strong>Accounts and objects (").Append(finding.AccountsTotal).Append("):</strong></p><ul class=\"accounts\">");
                foreach (var account in finding.Accounts)
                    output.Append("<li>").Append(E(account)).Append("</li>");
                output.Append("</ul>");
            }
            output.Append("</article>");
        }

        output.Append("</section><footer><p>Scan version ").Append(E(result.ScanVersion)).Append(" | SHA-256 ")
            .Append(E(result.ReportSha256)).Append("</p><p>Evidence for review, not a certification or a statement of compliance.</p>")
            .Append("<h2>LDAP queries run</h2><ol>");
        foreach (var query in result.QueryLog)
            output.Append("<li><code>").Append(E(query)).Append("</code></li>");
        output.Append("</ol></footer></main></body></html>");
        return output.ToString();
    }

    internal static string? LoadLogo(string? path)
    {
        if (path is null)
            return null;
        var extension = Path.GetExtension(path);
        if (!extension.Equals(".png", StringComparison.OrdinalIgnoreCase) && !extension.Equals(".svg", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Logo must be a PNG or SVG file.", nameof(path));
        var info = new FileInfo(path);
        if (!info.Exists)
            throw new ArgumentException("Logo file does not exist.", nameof(path));
        if (info.Length > 200 * 1024)
            throw new ArgumentException("Logo must not exceed 200 KB.", nameof(path));
        var bytes = File.ReadAllBytes(path);
        string mediaType;
        if (extension.Equals(".png", StringComparison.OrdinalIgnoreCase))
        {
            if (bytes.Length < 8 || !bytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
                throw new ArgumentException("Logo has a .png extension but is not a PNG file.", nameof(path));
            mediaType = "image/png";
        }
        else
        {
            var text = Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
            if (!text.StartsWith("<svg", StringComparison.OrdinalIgnoreCase) && !text.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Logo has a .svg extension but is not an SVG file.", nameof(path));
            ValidateSvg(text, path);
            mediaType = "image/svg+xml";
        }
        return $"data:{mediaType};base64,{Convert.ToBase64String(bytes)}";
    }

    private static void ValidateSvg(string text, string path)
    {
        XDocument document;
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 200 * 1024,
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException exception)
        {
            throw new ArgumentException("Logo is not safe, well-formed SVG.", nameof(path), exception);
        }

        if (document.Root?.Name.LocalName != "svg" || document.DescendantNodes().OfType<XProcessingInstruction>().Any())
            throw new ArgumentException("Logo is not a self-contained SVG.", nameof(path));
        var blockedElements = new HashSet<string>(["script", "style", "foreignObject", "iframe", "object", "embed"], StringComparer.OrdinalIgnoreCase);
        foreach (var element in document.Root.DescendantsAndSelf())
        {
            if (blockedElements.Contains(element.Name.LocalName))
                throw new ArgumentException("Logo contains active SVG content.", nameof(path));
            foreach (var attribute in element.Attributes())
            {
                if (attribute.Name.LocalName.Equals("base", StringComparison.OrdinalIgnoreCase) ||
                    attribute.Name.LocalName.StartsWith("on", StringComparison.OrdinalIgnoreCase) ||
                    attribute.Value.Contains("url(", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Logo contains active SVG content.", nameof(path));
                if (attribute.Name.LocalName is "href" or "src" &&
                    !attribute.Value.StartsWith('#') && !attribute.Value.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Logo contains an external resource.", nameof(path));
            }
        }
    }

    private static string E(string? value) => HtmlEncoder.Default.Encode(value ?? string.Empty);
}
