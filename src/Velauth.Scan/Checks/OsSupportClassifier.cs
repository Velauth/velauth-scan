using System.Text.RegularExpressions;

namespace Velauth.Scan.Checks;

public enum OsSupportStatus
{
    Unsupported,
    EndingSoon,
    Supported,
    Unknown,
}

public sealed record OsSupport(OsSupportStatus Status, string Product, DateOnly? EndOfSupport);

public static partial class OsSupportClassifier
{
    private sealed record Rule(Regex Test, string Product, DateOnly? End);

    private static readonly Rule[] Rules =
    [
        new(WindowsXp(), "Windows XP", new DateOnly(2014, 4, 8)),
        new(WindowsVista(), "Windows Vista", new DateOnly(2017, 4, 11)),
        new(Windows7(), "Windows 7", new DateOnly(2020, 1, 14)),
        new(Windows81(), "Windows 8.1", new DateOnly(2023, 1, 10)),
        new(Windows8(), "Windows 8", new DateOnly(2016, 1, 12)),
        new(Windows10(), "Windows 10", new DateOnly(2025, 10, 14)),
        new(Windows11(), "Windows 11", null),
        new(Server2003(), "Windows Server 2003", new DateOnly(2015, 7, 14)),
        new(Server2008R2(), "Windows Server 2008 R2", new DateOnly(2020, 1, 14)),
        new(Server2008(), "Windows Server 2008", new DateOnly(2020, 1, 14)),
        new(Server2012R2(), "Windows Server 2012 R2", new DateOnly(2023, 10, 10)),
        new(Server2012(), "Windows Server 2012", new DateOnly(2023, 10, 10)),
        new(Server2016(), "Windows Server 2016", new DateOnly(2027, 1, 12)),
        new(Server2019(), "Windows Server 2019", new DateOnly(2029, 1, 9)),
        new(Server2022(), "Windows Server 2022", new DateOnly(2031, 10, 14)),
        new(Server2025(), "Windows Server 2025", new DateOnly(2034, 11, 14)),
    ];

    public static OsSupport Classify(string? operatingSystem, DateTime nowUtc)
    {
        var text = operatingSystem?.Trim() ?? string.Empty;
        if (text.Length == 0)
            return new OsSupport(OsSupportStatus.Unknown, string.Empty, null);
        var rule = Rules.FirstOrDefault(candidate => candidate.Test.IsMatch(text));
        if (rule is null)
            return new OsSupport(OsSupportStatus.Unknown, string.Empty, null);
        if (rule.End is null)
            return new OsSupport(OsSupportStatus.Supported, rule.Product, null);
        var endUtc = rule.End.Value.ToDateTime(TimeOnly.MaxValue, DateTimeKind.Utc);
        var status = endUtc < nowUtc ? OsSupportStatus.Unsupported :
            endUtc - nowUtc <= TimeSpan.FromDays(365) ? OsSupportStatus.EndingSoon : OsSupportStatus.Supported;
        return new OsSupport(status, rule.Product, rule.End);
    }

    public static string Note(OsSupport support)
    {
        var esu = support.Product == "Windows 10" ? " unless covered by Extended Security Updates" : string.Empty;
        return support.Status switch
        {
            OsSupportStatus.Unsupported => $"{support.Product} reached end of support on {support.EndOfSupport:yyyy-MM-dd}{esu}. It no longer gets security fixes.",
            OsSupportStatus.EndingSoon => $"{support.Product} support ends on {support.EndOfSupport:yyyy-MM-dd}. Plan the upgrade.",
            _ => string.Empty,
        };
    }

    [GeneratedRegex("windows xp", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex WindowsXp();
    [GeneratedRegex("windows vista", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex WindowsVista();
    [GeneratedRegex(@"windows 7\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Windows7();
    [GeneratedRegex(@"windows 8\.1", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Windows81();
    [GeneratedRegex(@"windows 8\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Windows8();
    [GeneratedRegex("windows 10", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Windows10();
    [GeneratedRegex("windows 11", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Windows11();
    [GeneratedRegex("server 2003", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2003();
    [GeneratedRegex("server 2008 r2", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2008R2();
    [GeneratedRegex("server 2008", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2008();
    [GeneratedRegex("server 2012 r2", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2012R2();
    [GeneratedRegex("server 2012", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2012();
    [GeneratedRegex("server 2016", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2016();
    [GeneratedRegex("server 2019", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2019();
    [GeneratedRegex("server 2022", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2022();
    [GeneratedRegex("server 2025", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex Server2025();
}
