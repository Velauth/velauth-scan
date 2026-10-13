using Velauth.Scan.Model;

namespace Velauth.Scan.Directory;

public interface IScanDirectory
{
    DomainInfo GetDomain();
    IReadOnlyList<ScanUser>? GetUsers();
    IReadOnlyList<ScanComputer>? GetComputers();
    bool? IsLapsSchemaPresent();
    IReadOnlySet<string>? GetPrivilegedUserDns();
    IReadOnlySet<string>? GetProtectedUserDns();
    DomainPasswordPolicy? GetDefaultPasswordPolicy();
    ScanUser? GetKrbtgt();
    IReadOnlyList<(string Dn, ScanAcl Acl)>? GetContainerAcls();
    ScanAcl? GetAdminSdHolderAcl();
    ScanAcl? GetUserAcl(string dn);
    string? ResolveTrusteeName(string sid);
    string ResolveTrusteeKind(string sid);
    IReadOnlySet<string>? GetNestedMemberDnsOfSid(string sid);
    bool IsGroupSid(string sid);
    IReadOnlyList<string> QueryLog { get; }
}
