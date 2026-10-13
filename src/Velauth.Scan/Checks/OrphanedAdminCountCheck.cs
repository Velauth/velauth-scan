using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class OrphanedAdminCountCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "An account left with adminCount=1 may retain inheritance changes after privileged membership was removed.";
        const string fix = "1. Confirm the account is no longer privileged. 2. Set adminCount to 0. 3. Re-enable ACL inheritance and verify the resulting permissions.";
        var privileged = directory.GetPrivilegedUserDns();
        var users = directory.GetUsers();
        if (privileged is null || users is null)
            return CheckSupport.NotVisible(9, "Orphaned adminCount accounts", "Privileged access", Severity.Low, why, fix,
                "Privileged membership or user attributes could not be read.");
        // krbtgt is always protected (adminCount=1) by design and is not in a privileged group, so it is never an orphan.
        var matches = users.Where(user => user.AdminCount == 1 && !privileged.Contains(user.DistinguishedName) &&
                !user.SamAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase))
            .Select(CheckSupport.Name).ToArray();
        // adminCount is only present on accounts that were ever protected, so a missing value on an
        // ordinary user is normal and means "not set". It only means "could not be read" when the
        // attribute is missing on the privileged accounts too (hidden by permissions, or the
        // protected-account process has not run yet on a brand new domain). A privileged account that
        // shows adminCount=1 proves the attribute is readable.
        if (matches.Length == 0 && users.Any(user => user.AdminCount is null) &&
            !users.Any(user => user.AdminCount == 1 && privileged.Contains(user.DistinguishedName)))
            return CheckSupport.NotVisible(9, "Orphaned adminCount accounts", "Privileged access", Severity.Low, why, fix,
                "No privileged account showed adminCount, so the attribute could not be confirmed as readable.");
        return CheckSupport.Result(9, "Orphaned adminCount accounts", "Privileged access", Severity.Low, matches, why, fix);
    }
}
