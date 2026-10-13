using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class PrivilegedPasswordCheck : ICheck
{
    private const int PasswordNeverExpires = 0x10000;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Privileged credentials that never expire or remain unchanged for over 365 days give attackers a long-lived path to control.";
        const string fix = "1. Identify the owner of each account. 2. Clear Password never expires in ADUC where appropriate. 3. Rotate passwords older than 365 days and move services to managed service accounts.";
        var dns = directory.GetPrivilegedUserDns();
        var users = directory.GetUsers();
        if (dns is null || users is null)
            return CheckSupport.NotVisible(6, "Privileged password exposure", "Privileged access", Severity.High, why, fix,
                "The privileged-group membership or user query could not be read.", "Do privileged accounts rotate passwords at least annually?", "Velauth: Needs attention, Password never expires");

        var byDn = CheckSupport.UsersByDn(users);
        var matches = new List<string>();
        var unknown = false;
        foreach (var dn in dns)
        {
            if (!byDn.TryGetValue(dn, out var user))
            {
                unknown = true;
                continue;
            }
            var neverExpires = user.UserAccountControl is int uac && (uac & PasswordNeverExpires) != 0;
            var tooOld = user.PwdLastSetUtc is DateTime changed && changed < nowUtc.AddDays(-365);
            if (neverExpires || tooOld)
                matches.Add(CheckSupport.Name(user));
            else if (user.UserAccountControl is null || (user.PwdLastSetUtc is null && !user.MustChangePasswordAtNextLogon))
                unknown = true;
        }

        if (matches.Count == 0 && unknown)
            return CheckSupport.NotVisible(6, "Privileged password exposure", "Privileged access", Severity.High, why, fix,
                "One or more privileged password attributes could not be read.", "Do privileged accounts rotate passwords at least annually?", "Velauth: Needs attention, Password never expires");
        return CheckSupport.Result(6, "Privileged password exposure", "Privileged access", Severity.High, matches, why, fix,
            "Do privileged accounts rotate passwords at least annually?", "Velauth: Needs attention, Password never expires");
    }
}
