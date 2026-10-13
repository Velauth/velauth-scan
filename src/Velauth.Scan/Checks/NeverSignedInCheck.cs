using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class NeverSignedInCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Enabled accounts that have never signed in and are older than 30 days may be abandoned provisioning or dormant access.";
        const string fix = "1. Confirm each account was provisioned intentionally. 2. Disable accounts with no current owner. 3. Remove them after the retention period.";
        var users = directory.GetUsers();
        if (users is null)
            return CheckSupport.NotVisible(12, "Enabled accounts that never signed in", "Directory hygiene", Severity.Low, why, fix,
                "The user query could not be read.");
        var cutoff = nowUtc.AddDays(-30);
        var candidates = users.Where(user => user.Enabled && user.LastLogonUtc is null).ToArray();
        var matches = candidates.Where(user => user.WhenCreatedUtc is DateTime created && created < cutoff)
            .Select(CheckSupport.Name).ToArray();
        if (matches.Length == 0 && users.Any(user => user.UserAccountControl is null))
            return CheckSupport.NotVisible(12, "Enabled accounts that never signed in", "Directory hygiene", Severity.Low, why, fix,
                "userAccountControl could not be read for one or more accounts.");
        if (matches.Length == 0 && candidates.Any(user => user.WhenCreatedUtc is null))
            return CheckSupport.NotVisible(12, "Enabled accounts that never signed in", "Directory hygiene", Severity.Low, why, fix,
                "whenCreated could not be read for one or more accounts with no replicated sign-in timestamp.");
        return CheckSupport.Result(12, "Enabled accounts that never signed in", "Directory hygiene", Severity.Low, matches, why, fix);
    }
}
