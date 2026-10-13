using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Tests.Scan;

internal sealed class FakeScanDirectory : IScanDirectory
{
    public DomainInfo Domain { get; set; } = new("example.test", "EXAMPLE", "Windows Server 2016 or later", 2)
    {
        Sid = "S-1-5-21-100-200-300",
    };
    public IReadOnlyList<ScanUser>? Users { get; set; } = Array.Empty<ScanUser>();
    public IReadOnlyList<ScanComputer>? Computers { get; set; } = Array.Empty<ScanComputer>();
    public bool? LapsSchemaPresent { get; set; } = true;
    public IReadOnlySet<string>? PrivilegedUserDns { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlySet<string>? ProtectedUserDns { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public DomainPasswordPolicy? PasswordPolicy { get; set; } = new(14, 10, true, TimeSpan.FromDays(90));
    public ScanUser? Krbtgt { get; set; }
    public IReadOnlyList<(string Dn, ScanAcl Acl)>? ContainerAcls { get; set; } = Array.Empty<(string, ScanAcl)>();
    public ScanAcl? AdminSdHolderAcl { get; set; } = new() { Entries = Array.Empty<AclEntry>(), DaclProtected = true };
    public Dictionary<string, ScanAcl?> UserAcls { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string?> TrusteeNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> TrusteeKinds { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, IReadOnlySet<string>?> NestedMemberDns { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> GroupSids { get; } = new(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<string> QueryLog { get; set; } = Array.Empty<string>();

    public DomainInfo GetDomain() => Domain;
    public IReadOnlyList<ScanUser>? GetUsers() => Users;
    public IReadOnlyList<ScanComputer>? GetComputers() => Computers;
    public bool? IsLapsSchemaPresent() => LapsSchemaPresent;
    public IReadOnlySet<string>? GetPrivilegedUserDns() => PrivilegedUserDns;
    public IReadOnlySet<string>? GetProtectedUserDns() => ProtectedUserDns;
    public DomainPasswordPolicy? GetDefaultPasswordPolicy() => PasswordPolicy;
    public ScanUser? GetKrbtgt() => Krbtgt;
    public IReadOnlyList<(string Dn, ScanAcl Acl)>? GetContainerAcls() => ContainerAcls;
    public ScanAcl? GetAdminSdHolderAcl() => AdminSdHolderAcl;
    public ScanAcl? GetUserAcl(string dn) => UserAcls.TryGetValue(dn, out var acl)
        ? acl
        : new ScanAcl { Entries = Array.Empty<AclEntry>(), DaclProtected = false };
    public string? ResolveTrusteeName(string sid) => TrusteeNames.TryGetValue(sid, out var name) ? name : sid;
    public string ResolveTrusteeKind(string sid) => TrusteeKinds.TryGetValue(sid, out var kind) ? kind : IsGroupSid(sid) ? "Group" : "Account";
    public IReadOnlySet<string>? GetNestedMemberDnsOfSid(string sid) => NestedMemberDns.TryGetValue(sid, out var members)
        ? members
        : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public bool IsGroupSid(string sid) => GroupSids.Contains(sid);
}

internal static class TestObjects
{
    internal static ScanUser User(
        string name = "user1",
        int? uac = 0,
        DateTime? lastLogon = null,
        DateTime? created = null,
        DateTime? pwdLastSet = null,
        int? adminCount = 0,
        IReadOnlyList<string>? spns = null,
        bool enabled = true,
        string? dn = null) => new()
        {
            SamAccountName = name,
            DistinguishedName = dn ?? $"CN={name},DC=example,DC=test",
            Enabled = enabled,
            UserAccountControl = uac,
            LastLogonUtc = lastLogon,
            WhenCreatedUtc = created,
            PwdLastSetUtc = pwdLastSet,
            AdminCount = adminCount,
            ServicePrincipalNames = spns ?? Array.Empty<string>(),
            HasMailbox = false,
        };

    internal static ScanComputer Computer(
        string name = "PC1$",
        string? operatingSystem = "Windows 11 Pro",
        int? uac = 0,
        int? primaryGroupId = 515,
        bool enabled = true) => new()
        {
            SamAccountName = name,
            DistinguishedName = $"CN={name},DC=example,DC=test",
            Enabled = enabled,
            OperatingSystem = operatingSystem,
            UserAccountControl = uac,
            PrimaryGroupId = primaryGroupId,
            HasLapsExpiry = false,
        };
}
