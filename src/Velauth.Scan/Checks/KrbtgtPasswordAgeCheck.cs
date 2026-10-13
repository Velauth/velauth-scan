using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class KrbtgtPasswordAgeCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "The krbtgt key signs Kerberos tickets. A key older than 180 days extends the value of stolen ticket-signing material.";
        const string fix = "1. Follow Microsoft's krbtgt reset guidance. 2. Reset the password once. 3. Wait for replication and ticket expiry, then reset it a second time.";
        var user = directory.GetKrbtgt();
        if (user?.PwdLastSetUtc is not DateTime changed)
            return CheckSupport.NotVisible(10, "krbtgt password age", "Privileged access", Severity.High, why, fix,
                "The krbtgt account or pwdLastSet value could not be read.", "Is the krbtgt password rotated on a controlled schedule?");
        var matches = changed < nowUtc.AddDays(-180) ? new[] { CheckSupport.Name(user) } : Array.Empty<string>();
        return CheckSupport.Result(10, "krbtgt password age", "Privileged access", Severity.High, matches, why, fix,
            "Is the krbtgt password rotated on a controlled schedule?");
    }
}
