using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class AdminSdHolderCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "AdminSDHolder permissions are periodically copied to protected administrative accounts. A non-default powerful allow entry can grant lasting control of Tier-0 identities.";
        const string fix = "1. Compare AdminSDHolder with a known-good domain. 2. Use dsacls on CN=AdminSDHolder,CN=System or ADUC Advanced Security to remove the unauthorized allow entry. 3. Investigate protected accounts for copied permissions.";
        const string insurer = "Can helpdesk staff reset administrator passwords?";
        const string hint = "Velauth: approvals and Tier-0 guard";
        var acl = directory.GetAdminSdHolderAcl();
        if (acl is null)
            return CheckSupport.NotVisible(3, "AdminSDHolder powerful permissions", "Helpdesk blast radius", Severity.Critical,
                why, fix, "The AdminSDHolder DACL could not be read.", insurer, hint);

        var domainSid = directory.GetDomain().Sid;
        if (domainSid is null)
            return CheckSupport.NotVisible(3, "AdminSDHolder powerful permissions", "Helpdesk blast radius", Severity.Critical,
                why, fix, "The domain SID could not be read, so expected AdminSDHolder trustees cannot be identified safely.", insurer, hint);
        var entries = new List<string>();
        foreach (var ace in acl.Entries.Where(entry => entry.Allow && !ResetRights.IsIgnoredTrustee(entry.TrusteeSid, domainSid)))
        {
            var rights = DescribePowerfulRights(ace);
            if (rights.Count == 0)
                continue;
            var trustee = directory.ResolveTrusteeName(ace.TrusteeSid) ?? ace.TrusteeSid;
            entries.Add($"{trustee} ({ace.TrusteeSid}): {string.Join(", ", rights)}");
        }
        return CheckSupport.Result(3, "AdminSDHolder powerful permissions", "Helpdesk blast radius", Severity.Critical,
            entries, why, fix, insurer, hint);
    }

    private static IReadOnlyList<string> DescribePowerfulRights(AclEntry entry)
    {
        var mask = entry.AccessMask;
        if ((mask & ResetRights.GenericAll) != 0)
            return ["GenericAll"];
        if ((mask & ResetRights.FullControl) == ResetRights.FullControl)
            return ["Full control"];

        var rights = new List<string>();
        if ((mask & ResetRights.GenericWrite) != 0)
            rights.Add("GenericWrite");
        if ((mask & ResetRights.WriteDacl) != 0)
            rights.Add("WriteDacl");
        if ((mask & ResetRights.WriteOwner) != 0)
            rights.Add("WriteOwner");
        if ((mask & ResetRights.ExtendedRight) != 0 && IsEmpty(entry.ObjectType))
            rights.Add("All extended rights");
        else if ((mask & ResetRights.ExtendedRight) != 0 && entry.ObjectType == ResetRights.ResetPasswordGuid)
            rights.Add("Reset Password");
        if ((mask & ResetRights.WriteProperty) != 0 && IsEmpty(entry.ObjectType))
            rights.Add("Write all properties");
        return rights;
    }

    private static bool IsEmpty(Guid? value) => value is null || value == Guid.Empty;
}
