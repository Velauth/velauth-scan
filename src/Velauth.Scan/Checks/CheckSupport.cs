using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

internal static class CheckSupport
{
    internal const int AccountLimit = 200;

    internal static Finding Result(
        int id,
        string title,
        string category,
        Severity severity,
        IReadOnlyList<string> accounts,
        string why,
        string fix,
        string? insurerQuestion = null,
        string? velauthHint = null)
    {
        var ordered = accounts
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new Finding
        {
            Id = id,
            Title = title,
            Category = category,
            Severity = severity,
            Status = ordered.Length == 0 ? CheckStatus.Pass : CheckStatus.Fail,
            Count = ordered.Length,
            Accounts = ordered.Take(AccountLimit).ToArray(),
            AccountsTotal = ordered.Length,
            Why = why,
            Fix = fix,
            InsurerQuestion = insurerQuestion,
            VelauthHint = velauthHint,
        };
    }

    internal static Finding NotVisible(
        int id,
        string title,
        string category,
        Severity severity,
        string why,
        string fix,
        string reason,
        string? insurerQuestion = null,
        string? velauthHint = null) => new()
        {
            Id = id,
            Title = title,
            Category = category,
            Severity = severity,
            Status = CheckStatus.NotVisible,
            Count = null,
            Accounts = Array.Empty<string>(),
            AccountsTotal = null,
            Why = why,
            Fix = fix,
            InsurerQuestion = insurerQuestion,
            VelauthHint = velauthHint,
            NotVisibleReason = reason,
        };

    internal static string Name(ScanUser user) =>
        string.IsNullOrWhiteSpace(user.SamAccountName) ? user.DistinguishedName : user.SamAccountName;

    internal static string Name(ScanComputer computer) =>
        string.IsNullOrWhiteSpace(computer.SamAccountName) ? computer.DistinguishedName : computer.SamAccountName;

    internal static Dictionary<string, ScanUser> UsersByDn(IEnumerable<ScanUser> users) =>
        users.Where(user => !string.IsNullOrWhiteSpace(user.DistinguishedName))
            .GroupBy(user => user.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
}
