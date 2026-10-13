using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class WeakPasswordFlagsCheck : ICheck
{
    private const int PasswordNotRequired = 0x20;
    private const int ReversibleEncryption = 0x80;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "PASSWD_NOTREQD weakens account password requirements, and reversible encryption stores material that can be recovered as a password.";
        const string fix = "1. In ADUC, clear Store password using reversible encryption. 2. Clear Password not required with Set-ADAccountControl. 3. Reset the affected password.";
        var users = directory.GetUsers();
        if (users is null)
            return CheckSupport.NotVisible(14, "Weak password account flags", "Directory hygiene", Severity.High, why, fix,
                "The user query could not be read.", "Are reversible passwords and password-not-required flags prohibited?");
        var unknown = users.Any(user => user.Enabled && user.UserAccountControl is null);
        var matches = users.Where(user => user.Enabled && user.UserAccountControl is int uac &&
                (uac & (PasswordNotRequired | ReversibleEncryption)) != 0)
            .Select(CheckSupport.Name).ToArray();
        if (matches.Length == 0 && unknown)
            return CheckSupport.NotVisible(14, "Weak password account flags", "Directory hygiene", Severity.High, why, fix,
                "One or more userAccountControl values could not be read.", "Are reversible passwords and password-not-required flags prohibited?");
        return CheckSupport.Result(14, "Weak password account flags", "Directory hygiene", Severity.High, matches, why, fix,
            "Are reversible passwords and password-not-required flags prohibited?");
    }
}
