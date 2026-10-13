using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class PrivilegedDailyUseCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Admin accounts used for email and browsing are the usual way admin credentials are stolen.";
        const string fix = "Use separate accounts: a normal account for daily work, and a separate admin account with no mailbox.";
        const string insurer = "Do administrators use separate accounts for administration?";
        const string hint = "Velauth: Tier-0 guard and approvals for admin accounts";
        var privileged = directory.GetPrivilegedUserDns();
        var users = directory.GetUsers();
        if (privileged is null || users is null)
            return CheckSupport.NotVisible(8, "Privileged accounts that look like daily-use accounts", "Privileged access", Severity.Medium,
                why, fix, "The privileged-group membership or user query could not be read.", insurer, hint);

        var privilegedUsers = CheckSupport.UsersByDn(users).Where(pair => privileged.Contains(pair.Key)).Select(pair => pair.Value).ToArray();
        if (privilegedUsers.Length > 0 && privilegedUsers.All(user => user.HasMailbox is null))
            return CheckSupport.NotVisible(8, "Privileged accounts that look like daily-use accounts", "Privileged access", Severity.Medium,
                why, fix, "The mailbox attributes could not be read for privileged users.", insurer, hint);

        var cutoff = nowUtc.AddDays(-14);
        var matches = privilegedUsers.Where(user =>
                !user.SamAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) &&
                (!user.SamAccountName.Equals("Administrator", StringComparison.OrdinalIgnoreCase) || user.HasMailbox == true) &&
                (user.HasMailbox == true || user.LastLogonUtc is DateTime signIn && signIn >= cutoff))
            .Select(CheckSupport.Name).ToArray();
        return CheckSupport.Result(8, "Privileged accounts that look like daily-use accounts", "Privileged access", Severity.Medium,
            matches, why, fix, insurer, hint);
    }
}
