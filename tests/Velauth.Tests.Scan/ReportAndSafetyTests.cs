using System.Text.Json;
using System.Text.RegularExpressions;
using Velauth.Scan;
using Velauth.Scan.Directory;
using Velauth.Scan.Model;
using Velauth.Scan.Report;

namespace Velauth.Tests.Scan;

public sealed class ReportAndSafetyTests
{
    [Fact]
    public void HtmlEncodesDirectoryAndBrandingStrings()
    {
        var finding = Finding(11, CheckStatus.Fail) with
        {
            Accounts = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
            Count = 2,
            AccountsTotal = 2,
        };
        var result = ScanScoring.Create("<script>domain</script>", DateTime.UnixEpoch, [finding],
            ["Base: <script> | Filter: (x=<script>)"]);
        var html = ReportWriter.RenderHtml(result, "\"><img src=x onerror=alert(1)>");

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img src=x", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html);
        Assert.Contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", html);
    }

    [Fact]
    public void CanonicalFindingHashIsStableAcrossFindingAndAccountOrder()
    {
        var first = Finding(5, CheckStatus.Fail) with { Accounts = ["z", "a"], Count = 2, AccountsTotal = 2 };
        var second = Finding(6, CheckStatus.Pass);
        Assert.Equal(ScanScoring.FindingsSha256([first, second]), ScanScoring.FindingsSha256([second, first with { Accounts = ["a", "z"] }]));
    }

    [Fact]
    public void JsonContainsSchemaVersionAndHash()
    {
        var result = ScanScoring.Create("example.test", DateTime.UnixEpoch, [Finding(5, CheckStatus.Pass)], []);
        var json = JsonSerializer.Serialize(result, JsonOptions.Indented);
        using var document = JsonDocument.Parse(json);
        Assert.Equal(1, document.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(64, document.RootElement.GetProperty("reportSha256").GetString()!.Length);
    }

    [Fact]
    public void JsonAndHtmlContainEncodedBlastRadiusDetail()
    {
        var details = new ResetBlastRadius
        {
            ResettableEnabledUsers = 1,
            EnabledUsers = 2,
            DelegatedPrincipals = 1,
            DelegatedPeople = 1,
            TopPrincipals = [new PrincipalReach("<script>bad</script>", "Group", 1, 1)],
        };
        var reset = Finding(1, CheckStatus.Fail) with { Count = 1, AccountsTotal = 1, Details = details };
        var privileged = Finding(2, CheckStatus.Pass);
        var result = ScanScoring.Create("example.test", DateTime.UnixEpoch, [reset, privileged], []);
        var json = JsonSerializer.Serialize(result, JsonOptions.Indented);
        var html = ReportWriter.RenderHtml(result);

        Assert.Contains("\"blastRadius\"", json);
        Assert.Contains("1 of 2 enabled accounts", html);
        Assert.Contains("&lt;script&gt;bad&lt;/script&gt;", html);
        Assert.DoesNotContain("<script>bad</script>", html);
    }

    [Fact]
    public void LowCoverageIsIncompleteAndNotVisibleDoesNotLowerLetterGrade()
    {
        var findings = Enumerable.Range(1, 20).Select(id => Finding(id, id <= 5 ? CheckStatus.Pass : CheckStatus.NotVisible)).ToArray();
        var result = ScanScoring.Create("example.test", DateTime.UnixEpoch, findings, []);
        Assert.Equal("Incomplete", result.Grade);
        Assert.Equal(5, result.Coverage.Completed);
    }

    [Fact]
    public void SliceOneLabResultGradesC()
    {
        var findings = new[]
        {
            Finding(1, CheckStatus.Fail) with { Severity = Severity.High },
            Finding(2, CheckStatus.Fail) with { Severity = Severity.Medium },
            Finding(3, CheckStatus.Fail) with { Severity = Severity.Medium },
            Finding(4, CheckStatus.Fail) with { Severity = Severity.Medium },
            Finding(5, CheckStatus.Fail) with { Severity = Severity.Low },
            Finding(6, CheckStatus.Fail) with { Severity = Severity.Low },
        };
        Assert.Equal("C", ScanScoring.Grade(findings));
    }

    [Fact]
    public void CleanDomainGradesAAndOneCriticalGradesD()
    {
        Assert.Equal("A", ScanScoring.Grade([Finding(1, CheckStatus.Pass)]));
        Assert.Equal("D", ScanScoring.Grade([Finding(1, CheckStatus.Fail) with { Severity = Severity.Critical }]));
    }

    [Theory]
    [InlineData(4, "A")]
    [InlineData(5, "B")]
    [InlineData(14, "B")]
    [InlineData(15, "C")]
    [InlineData(29, "C")]
    [InlineData(30, "D")]
    [InlineData(49, "D")]
    [InlineData(50, "F")]
    public void ScoringBoundaries(int points, string expected)
    {
        var findings = Enumerable.Range(1, points)
            .Select(id => Finding(id, CheckStatus.Fail) with { Severity = Severity.Low });
        Assert.Equal(expected, ScanScoring.Grade(findings));
    }

    [Theory]
    [InlineData(69, false)]
    [InlineData(70, true)]
    public void CoverageBoundary(decimal percent, bool complete)
    {
        Assert.Equal(complete, ScanScoring.IsCoverageComplete(percent));
    }

    [Fact]
    public void SourceContainsNoDirectoryWritePrimitives()
    {
        var forbidden = new[] { "CommitChanges", "SetPassword", "Invoke(", "DeleteTree" };
        AssertSourceDoesNotContain(forbidden);
    }

    [Fact]
    public void SourceContainsNoNonLdapNetworkOrProcessApis()
    {
        var forbidden = new[] { "HttpClient", "WebClient", "TcpClient", "Socket", "WebRequest", "Process.Start" };
        AssertSourceDoesNotContain(forbidden);
    }

    [Fact]
    public void ScannerSourcesContainNoEmDash()
    {
        AssertSourceDoesNotContain(["\u2014"]);
    }

    [Fact]
    public void LapsPasswordAttributesAreNeverRequested()
    {
        var forbidden = new[] { "msLAPS-Password", "msLAPS-EncryptedPassword", "ms-Mcs-AdmPwd" };
        foreach (var attribute in forbidden)
        {
            Assert.DoesNotContain(LdapScanDirectory.QueryCatalog, query => Regex.IsMatch(query, $@"(?<![A-Za-z0-9-]){Regex.Escape(attribute)}(?![A-Za-z0-9-])"));
            Assert.DoesNotContain(LdapScanDirectory.ComputerAttributes, candidate => candidate.Equals(attribute, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void SvgLogoCannotContainActiveOrExternalContent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"velauth-scan-{Guid.NewGuid():N}.svg");
        try
        {
            File.WriteAllText(path, "<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"https://example.test/tracker.png\"/></svg>");
            var exception = Assert.Throws<ArgumentException>(() => ReportWriter.LoadLogo(path));
            Assert.Contains("external resource", exception.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static void AssertSourceDoesNotContain(IReadOnlyList<string> forbidden)
    {
        var sourceRoot = FindRepositoryRoot();
        var files = System.IO.Directory.EnumerateFiles(Path.Combine(sourceRoot, "src", "Velauth.Scan"), "*", SearchOption.AllDirectories)
            .Where(path => Path.GetExtension(path) is ".cs" or ".csproj" or ".md");
        foreach (var file in files)
        {
            var content = File.ReadAllText(file);
            foreach (var value in forbidden)
                Assert.DoesNotContain(value, content, StringComparison.Ordinal);
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Velauth.Scan.sln")))
            current = current.Parent;
        return current?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
    }

    private static Finding Finding(int id, CheckStatus status) => new()
    {
        Id = id,
        Title = $"Finding {id}",
        Category = "Directory hygiene",
        Severity = Severity.Medium,
        Status = status,
        Count = status == CheckStatus.NotVisible ? null : 0,
        Accounts = Array.Empty<string>(),
        AccountsTotal = status == CheckStatus.NotVisible ? null : 0,
        Why = "Why.",
        Fix = "1. Fix it.",
        NotVisibleReason = status == CheckStatus.NotVisible ? "Not readable." : null,
    };
}
