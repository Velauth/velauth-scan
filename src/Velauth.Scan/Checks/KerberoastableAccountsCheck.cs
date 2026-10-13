using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class KerberoastableAccountsCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Any authenticated domain user can request service tickets for SPN-bearing user accounts and attempt to crack their password offline.";
        const string fix = "1. Inventory each SPN and service owner. 2. Use a group managed service account where possible. 3. Otherwise set a long random password and remove unnecessary privilege.";
        var users = directory.GetUsers();
        var privileged = directory.GetPrivilegedUserDns();
        if (users is null || privileged is null)
            return CheckSupport.NotVisible(16, "Kerberoastable user accounts", "Attack paths", Severity.High, why, fix,
                "The user query or privileged membership could not be read.", "Are service accounts resistant to offline password cracking?");
        var unknown = users.Any(user => user.Enabled && !user.SamAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) &&
            (user.UserAccountControl is null || user.ServicePrincipalNames is null));
        var exposed = users.Where(user => user.Enabled && !user.SamAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) &&
                user.ServicePrincipalNames is { Count: > 0 }).ToArray();
        if (exposed.Length == 0 && unknown)
            return CheckSupport.NotVisible(16, "Kerberoastable user accounts", "Attack paths", Severity.High, why, fix,
                "One or more servicePrincipalName values could not be read.", "Are service accounts resistant to offline password cracking?");
        var names = exposed.Select(CheckSupport.Name).ToArray();
        var severity = exposed.Any(user => privileged.Contains(user.DistinguishedName)) ? Severity.High : Severity.Medium;
        return CheckSupport.Result(16, "Kerberoastable user accounts", "Attack paths", severity, names, why, fix,
            "Are service accounts resistant to offline password cracking?");
    }
}
