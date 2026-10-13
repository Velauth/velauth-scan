using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class PrivilegedProtectionCheck : ICheck
{
    private const int NotDelegated = 0x100000;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Protected Users membership or the sensitive-and-not-delegated flag reduces credential theft through legacy authentication and delegation.";
        const string fix = "1. Test each account for compatibility. 2. Add compatible accounts to Protected Users. 3. In ADUC, select Account is sensitive and cannot be delegated.";
        var privileged = directory.GetPrivilegedUserDns();
        var protectedUsers = directory.GetProtectedUserDns();
        var users = directory.GetUsers();
        if (privileged is null || protectedUsers is null || users is null)
            return CheckSupport.NotVisible(7, "Privileged accounts without delegation protection", "Privileged access", Severity.Medium, why, fix,
                "Protected Users, privileged membership, or user attributes could not be read.", "Are privileged accounts protected from credential delegation?");

        var byDn = CheckSupport.UsersByDn(users);
        var matches = new List<string>();
        var unknown = false;
        foreach (var dn in privileged)
        {
            if (!byDn.TryGetValue(dn, out var user) || user.UserAccountControl is null)
            {
                unknown = true;
                continue;
            }
            if (!protectedUsers.Contains(dn) && (user.UserAccountControl.Value & NotDelegated) == 0)
                matches.Add(CheckSupport.Name(user));
        }
        if (matches.Count == 0 && unknown)
            return CheckSupport.NotVisible(7, "Privileged accounts without delegation protection", "Privileged access", Severity.Medium, why, fix,
                "One or more privileged userAccountControl values could not be read.", "Are privileged accounts protected from credential delegation?");
        return CheckSupport.Result(7, "Privileged accounts without delegation protection", "Privileged access", Severity.Medium, matches, why, fix,
            "Are privileged accounts protected from credential delegation?");
    }
}
