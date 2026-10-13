using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class AsRepRoastableAccountsCheck : ICheck
{
    private const int DontRequirePreauthentication = 0x400000;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Accounts without Kerberos preauthentication allow an unauthenticated attacker to request encrypted material for offline password cracking.";
        const string fix = "1. In ADUC, open the Account tab. 2. Clear Do not require Kerberos preauthentication. 3. Reset weak passwords and investigate dependencies.";
        var users = directory.GetUsers();
        if (users is null)
            return CheckSupport.NotVisible(17, "AS-REP roastable accounts", "Attack paths", Severity.High, why, fix,
                "The user query could not be read.");
        var unknown = users.Any(user => user.Enabled && user.UserAccountControl is null);
        var matches = users.Where(user => user.Enabled && user.UserAccountControl is int uac && (uac & DontRequirePreauthentication) != 0)
            .Select(CheckSupport.Name).ToArray();
        if (matches.Length == 0 && unknown)
            return CheckSupport.NotVisible(17, "AS-REP roastable accounts", "Attack paths", Severity.High, why, fix,
                "One or more userAccountControl values could not be read.");
        return CheckSupport.Result(17, "AS-REP roastable accounts", "Attack paths", Severity.High, matches, why, fix);
    }
}
