using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class StaleSignInCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Enabled accounts unused for 90 days can be forgotten entry points. lastLogonTimestamp is replicated with normal replication lag, so this is an approximate age.";
        const string fix = "1. Confirm the account owner and business need. 2. Disable unused accounts in ADUC. 3. Delete them only after the retention period and dependency review.";
        var users = directory.GetUsers();
        if (users is null)
            return CheckSupport.NotVisible(11, "Enabled accounts inactive for 90 days", "Directory hygiene", Severity.Medium, why, fix,
                "The user query could not be read.", "Are inactive accounts disabled within 90 days?", "Velauth: Needs attention, Inactive accounts");
        var cutoff = nowUtc.AddDays(-90);
        var candidates = users.Where(user => user.Enabled && user.LastLogonUtc is DateTime last && last < cutoff).ToArray();
        var matches = candidates.Where(user => user.WhenCreatedUtc is DateTime created && created < cutoff)
            .Select(CheckSupport.Name).ToArray();
        if (matches.Length == 0 && users.Any(user => user.UserAccountControl is null))
            return CheckSupport.NotVisible(11, "Enabled accounts inactive for 90 days", "Directory hygiene", Severity.Medium, why, fix,
                "userAccountControl could not be read for one or more accounts.", "Are inactive accounts disabled within 90 days?", "Velauth: Needs attention, Inactive accounts");
        if (matches.Length == 0 && candidates.Any(user => user.WhenCreatedUtc is null))
            return CheckSupport.NotVisible(11, "Enabled accounts inactive for 90 days", "Directory hygiene", Severity.Medium, why, fix,
                "whenCreated could not be read for one or more inactive accounts.", "Are inactive accounts disabled within 90 days?", "Velauth: Needs attention, Inactive accounts");
        return CheckSupport.Result(11, "Enabled accounts inactive for 90 days", "Directory hygiene", Severity.Medium, matches, why, fix,
            "Are inactive accounts disabled within 90 days?", "Velauth: Needs attention, Inactive accounts");
    }
}
