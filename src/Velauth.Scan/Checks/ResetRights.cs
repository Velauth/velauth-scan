using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public static class ResetRights
{
    // Microsoft ADS_RIGHT_DS_CONTROL_ACCESS (ExtendedRight).
    public const int ExtendedRight = 0x00000100;
    // Microsoft ADS_RIGHT_GENERIC_ALL.
    public const int GenericAll = 0x10000000;
    // Microsoft ADS_RIGHT_GENERIC_WRITE.
    public const int GenericWrite = 0x40000000;
    // Microsoft WRITE_DAC and WRITE_OWNER standard access rights.
    public const int WriteDacl = 0x00040000;
    public const int WriteOwner = 0x00080000;
    // Microsoft ADS_RIGHT_DS_WRITE_PROP.
    public const int WriteProperty = 0x00000020;
    // Active Directory full control combines the standard and directory-service rights below.
    public const int FullControl = 0x000F01FF;

    // Microsoft User-Force-Change-Password controlAccessRight (Reset Password).
    public static readonly Guid ResetPasswordGuid = new("00299570-246d-11d0-a768-00aa006e0529");
    // Microsoft user class schemaIDGUID. Confirmed against a real domain: the lab ACEs carry bf967aba-0de6-11d0-a285-00aa003049e2.
    public static readonly Guid UserClassGuid = new("bf967aba-0de6-11d0-a285-00aa003049e2");

    public static bool GrantsResetPassword(AclEntry entry, bool onUserObject)
    {
        if (!AppliesToUserClass(entry) || (!onUserObject && !entry.ContainerInherit))
            return false;

        var mask = entry.AccessMask;
        if ((mask & GenericAll) != 0 || (mask & FullControl) == FullControl)
            return true;

        return (mask & ExtendedRight) != 0 && IsEmptyOr(entry.ObjectType, ResetPasswordGuid);
    }

    public static bool AppliesToUser(AclEntry entry, string containerDn, string userDn)
    {
        if (!GrantsResetPassword(entry, onUserObject: false) || !IsDescendantOf(userDn, containerDn))
            return false;
        return !entry.NoPropagateInherit || IsImmediateChildOf(userDn, containerDn);
    }

    internal static IReadOnlySet<(string TrusteeSid, string UserDn)> EffectiveContainerGrants(
        IReadOnlyList<(string Dn, ScanAcl Acl)> containers,
        IReadOnlyList<ScanUser> users)
    {
        var allows = new HashSet<(string TrusteeSid, string UserDn)>(TrusteeUserComparer.Instance);
        var denies = new HashSet<(string TrusteeSid, string UserDn)>(TrusteeUserComparer.Instance);

        foreach (var (containerDn, acl) in containers)
        {
            foreach (var entry in acl.Entries)
            {
                foreach (var user in users)
                {
                    if (!AppliesToUser(entry, containerDn, user.DistinguishedName) ||
                        CrossesProtectedContainer(containerDn, user.DistinguishedName, containers))
                        continue;
                    var pair = (entry.TrusteeSid, user.DistinguishedName);
                    if (entry.Allow)
                        allows.Add(pair);
                    else
                        denies.Add(pair);
                }
            }
        }

        allows.ExceptWith(denies);
        return allows;
    }

    private static bool CrossesProtectedContainer(
        string sourceContainerDn,
        string userDn,
        IReadOnlyList<(string Dn, ScanAcl Acl)> containers) =>
        containers.Any(candidate => candidate.Acl.DaclProtected &&
            !candidate.Dn.Equals(sourceContainerDn, StringComparison.OrdinalIgnoreCase) &&
            IsDescendantOf(candidate.Dn, sourceContainerDn) &&
            IsDescendantOf(userDn, candidate.Dn));

    internal static bool IsIgnoredTrustee(string sid, string? domainSid)
    {
        if (sid.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase) ||
            sid.Equals("S-1-5-32-544", StringComparison.OrdinalIgnoreCase) ||
            sid.Equals("S-1-3-0", StringComparison.OrdinalIgnoreCase) ||
            sid.Equals("S-1-5-10", StringComparison.OrdinalIgnoreCase) ||
            sid.Equals("S-1-5-9", StringComparison.OrdinalIgnoreCase))
            return true;

        return domainSid is not null &&
            (sid.Equals($"{domainSid}-512", StringComparison.OrdinalIgnoreCase) ||
             sid.Equals($"{domainSid}-519", StringComparison.OrdinalIgnoreCase));
    }

    internal static bool IsBroadTrustee(string sid, string? domainSid) =>
        IsCriticalBroadTrustee(sid, domainSid) || sid.Equals("S-1-5-32-548", StringComparison.OrdinalIgnoreCase);

    internal static bool IsCriticalBroadTrustee(string sid, string? domainSid) =>
        sid.Equals("S-1-1-0", StringComparison.OrdinalIgnoreCase) ||
        sid.Equals("S-1-5-11", StringComparison.OrdinalIgnoreCase) ||
        domainSid is not null && sid.Equals($"{domainSid}-513", StringComparison.OrdinalIgnoreCase);

    private static bool AppliesToUserClass(AclEntry entry) => IsEmptyOr(entry.InheritedObjectType, UserClassGuid);

    private static bool IsEmptyOr(Guid? value, Guid expected) => value is null || value == Guid.Empty || value == expected;

    private static bool IsDescendantOf(string childDn, string containerDn) =>
        childDn.Length > containerDn.Length &&
        childDn.EndsWith(containerDn, StringComparison.OrdinalIgnoreCase) &&
        childDn[childDn.Length - containerDn.Length - 1] == ',';

    private static bool IsImmediateChildOf(string childDn, string containerDn)
    {
        if (!IsDescendantOf(childDn, containerDn))
            return false;
        var relative = childDn[..(childDn.Length - containerDn.Length - 1)];
        var escaped = false;
        foreach (var character in relative)
        {
            if (escaped)
            {
                escaped = false;
                continue;
            }
            if (character == '\\')
            {
                escaped = true;
                continue;
            }
            if (character == ',')
                return false;
        }
        return true;
    }

    private sealed class TrusteeUserComparer : IEqualityComparer<(string TrusteeSid, string UserDn)>
    {
        internal static TrusteeUserComparer Instance { get; } = new();

        public bool Equals((string TrusteeSid, string UserDn) x, (string TrusteeSid, string UserDn) y) =>
            StringComparer.OrdinalIgnoreCase.Equals(x.TrusteeSid, y.TrusteeSid) &&
            StringComparer.OrdinalIgnoreCase.Equals(x.UserDn, y.UserDn);

        public int GetHashCode((string TrusteeSid, string UserDn) value) =>
            HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(value.TrusteeSid),
                StringComparer.OrdinalIgnoreCase.GetHashCode(value.UserDn));
    }
}
