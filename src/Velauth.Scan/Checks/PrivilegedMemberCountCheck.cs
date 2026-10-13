using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class PrivilegedMemberCountCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Small, named privileged groups limit the number of accounts an attacker can use for domain-wide control.";
        const string fix = "1. Open Active Directory Users and Computers. 2. Review each listed privileged group. 3. Remove accounts that do not require standing privilege.";
        var dns = directory.GetPrivilegedUserDns();
        var users = directory.GetUsers();
        if (dns is null || users is null)
        {
            return CheckSupport.NotVisible(5, "Privileged group members", "Privileged access", Severity.Info, why, fix,
                "The privileged-group membership or user query could not be read.", "Are privileged group memberships restricted and reviewed?");
        }

        var byDn = CheckSupport.UsersByDn(users);
        var names = dns.Select(dn => byDn.TryGetValue(dn, out var user) ? CheckSupport.Name(user) : dn)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
        return new Finding
        {
            Id = 5,
            Title = "Privileged group members",
            Category = "Privileged access",
            Severity = Severity.Info,
            Status = names.Length > 5 ? CheckStatus.Fail : CheckStatus.Pass,
            Count = names.Length,
            Accounts = names.Take(CheckSupport.AccountLimit).ToArray(),
            AccountsTotal = names.Length,
            Why = why,
            Fix = fix,
            InsurerQuestion = "Are privileged group memberships restricted and reviewed?",
        };
    }
}
