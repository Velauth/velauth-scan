using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Velauth.Scan.Model;

namespace Velauth.Scan;

public sealed record CoverageInfo(int Completed, int Total, decimal Percent);

public sealed record ScanResult
{
    public int SchemaVersion { get; init; } = 1;
    public required string DomainName { get; init; }
    public required string ScanVersion { get; init; }
    public required DateTime GeneratedUtc { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public ResetBlastRadius? BlastRadius { get; init; }
    public required CoverageInfo Coverage { get; init; }
    public required string Grade { get; init; }
    public required IReadOnlyList<string> QueryLog { get; init; }
    public required string ReportSha256 { get; init; }
}

public static class ScanScoring
{
    public const int ChecksInVersion = 20;

    public static ScanResult Create(string domainName, DateTime generatedUtc, IReadOnlyList<Finding> findings, IReadOnlyList<string> queryLog)
    {
        var ordered = findings.OrderBy(finding => finding.Id).ToArray();
        var completed = ordered.Count(finding => finding.Status != CheckStatus.NotVisible);
        var percent = Math.Round(completed * 100m / ChecksInVersion, 1, MidpointRounding.AwayFromZero);
        return new ScanResult
        {
            DomainName = domainName,
            ScanVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0",
            GeneratedUtc = generatedUtc,
            Findings = ordered,
            BlastRadius = ordered.FirstOrDefault(finding => finding.Id == 1)?.Details as ResetBlastRadius,
            Coverage = new CoverageInfo(completed, ChecksInVersion, percent),
            Grade = IsCoverageComplete(percent) ? Grade(ordered) : "Incomplete",
            QueryLog = queryLog.ToArray(),
            ReportSha256 = FindingsSha256(ordered),
        };
    }

    public static bool IsCoverageComplete(decimal percent) => percent >= 70m;

    // Exact formula: sum failed findings once each. Critical=25, High=10, Medium=4,
    // Low=1, Info=0. A=0-4, B=5-14, C=15-29, D=30-49, F=50+.
    // A Critical failure caps the result at D; a High failure caps it at C.
    public static string Grade(IEnumerable<Finding> findings)
    {
        var failures = findings.Where(finding => finding.Status == CheckStatus.Fail).ToArray();
        var score = failures.Sum(finding => finding.Severity switch
        {
            Severity.Critical => 25,
            Severity.High => 10,
            Severity.Medium => 4,
            Severity.Low => 1,
            _ => 0,
        });
        var grade = score switch
        {
            <= 4 => "A",
            <= 14 => "B",
            <= 29 => "C",
            <= 49 => "D",
            _ => "F",
        };
        if (failures.Any(finding => finding.Severity == Severity.Critical) && grade is "A" or "B" or "C")
            return "D";
        if (failures.Any(finding => finding.Severity == Severity.High) && grade is "A" or "B")
            return "C";
        return grade;
    }

    public static string FindingsSha256(IEnumerable<Finding> findings)
    {
        var stable = findings.OrderBy(finding => finding.Id).Select(finding => new
        {
            finding.Id,
            finding.Title,
            finding.Category,
            finding.Severity,
            finding.Status,
            finding.Count,
            Accounts = finding.Accounts.OrderBy(value => value, StringComparer.Ordinal).ToArray(),
            finding.AccountsTotal,
            finding.Why,
            finding.Fix,
            finding.InsurerQuestion,
            finding.VelauthHint,
            finding.NotVisibleReason,
            finding.Details,
        });
        var bytes = JsonSerializer.SerializeToUtf8Bytes(stable, JsonOptions.Canonical);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}

public static class JsonOptions
{
    public static JsonSerializerOptions Canonical { get; } = Create(false);
    public static JsonSerializerOptions Indented { get; } = Create(true);

    private static JsonSerializerOptions Create(bool indented)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = indented,
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }
}
