using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class NonServicePasswordNeverExpiresCheck : ICheck
{
    private const int PasswordNeverExpires = 0x10000;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "A non-service user password that never expires can remain useful to an attacker indefinitely. Accounts with SPNs are noted as service accounts and excluded here, and privileged accounts are covered by the privileged password check.";
        const string fix = "1. Clear Password never expires in ADUC. 2. Require a password change. 3. For actual services, migrate to a group managed service account.";
        var users = directory.GetUsers();
        if (users is null)
            return CheckSupport.NotVisible(13, "Password never expires on non-service accounts", "Directory hygiene", Severity.Medium, why, fix,
                "The user query could not be read.", "Do ordinary user passwords expire or rotate?", "Velauth: Needs attention, Password never expires");
        var unknown = users.Any(user => user.Enabled && (user.UserAccountControl is null ||
            (user.UserAccountControl is int value && (value & PasswordNeverExpires) != 0 && user.ServicePrincipalNames is null)));
        // Privileged accounts are reported once, by check 6. When the privileged set cannot be read nothing is excluded.
        var privileged = directory.GetPrivilegedUserDns();
        var matches = users.Where(user => user.Enabled && (privileged is null || !privileged.Contains(user.DistinguishedName)) && user.UserAccountControl is int uac && (uac & PasswordNeverExpires) != 0 &&
                user.ServicePrincipalNames is { Count: 0 })
            .Select(CheckSupport.Name).ToArray();
        if (matches.Length == 0 && unknown)
            return CheckSupport.NotVisible(13, "Password never expires on non-service accounts", "Directory hygiene", Severity.Medium, why, fix,
                "One or more userAccountControl or servicePrincipalName values could not be read.", "Do ordinary user passwords expire or rotate?", "Velauth: Needs attention, Password never expires");
        return CheckSupport.Result(13, "Password never expires on non-service accounts", "Directory hygiene", Severity.Medium, matches, why, fix,
            "Do ordinary user passwords expire or rotate?", "Velauth: Needs attention, Password never expires");
    }
}
