using System.Collections;
using System.DirectoryServices;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Velauth.Scan.Model;

namespace Velauth.Scan.Directory;

public sealed partial class LdapScanDirectory : IScanDirectory
{
    private const int Disabled = 0x2;
    private const string MatchingRuleInChain = "1.2.840.113556.1.4.1941";
    private static readonly int[] PrivilegedRids = [512, 519, 518, 544, 548, 551, 549, 550];
    private static readonly string[] UserAttributes =
    [
        "sAMAccountName", "distinguishedName", "userAccountControl", "lastLogonTimestamp", "whenCreated",
        "pwdLastSet", "adminCount", "servicePrincipalName", "mail", "msExchMailboxGuid",
    ];
    internal static readonly string[] ComputerAttributes =
    [
        "sAMAccountName", "distinguishedName", "userAccountControl", "operatingSystem", "primaryGroupID",
        "msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime",
    ];

    private readonly string? _domainController;
    private readonly string? _requestedDomain;
    private readonly List<string> _queryLog = [];
    private readonly object _sync = new();
    private string? _baseDn;
    private string? _configurationDn;
    private string? _schemaDn;
    private DomainInfo? _domain;
    private IReadOnlyList<ScanUser>? _users;
    private bool _usersAttempted;
    private IReadOnlyList<ScanComputer>? _computers;
    private bool _computersAttempted;
    private bool? _lapsSchemaPresent;
    private bool _lapsSchemaAttempted;
    private IReadOnlySet<string>? _privileged;
    private bool _privilegedAttempted;
    private IReadOnlySet<string>? _protected;
    private bool _protectedAttempted;
    private DomainPasswordPolicy? _policy;
    private bool _policyAttempted;
    private ScanUser? _krbtgt;
    private bool _krbtgtAttempted;
    private IReadOnlyList<(string Dn, ScanAcl Acl)>? _containerAcls;
    private bool _containerAclsAttempted;
    private ScanAcl? _adminSdHolderAcl;
    private bool _adminSdHolderAclAttempted;
    private readonly Dictionary<string, ScanAcl?> _userAcls = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PrincipalLookup?> _principalLookups = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, IReadOnlySet<string>?> _principalMembers = new(StringComparer.OrdinalIgnoreCase);

    public LdapScanDirectory(string? domainController = null, string? domain = null)
    {
        if (!string.IsNullOrWhiteSpace(domainController) && !HostName().IsMatch(domainController))
            throw new ArgumentException("The domain controller must be a valid DNS host name.", nameof(domainController));
        if (!string.IsNullOrWhiteSpace(domain) && !DomainName().IsMatch(domain))
            throw new ArgumentException("The domain must be a valid DNS domain name.", nameof(domain));
        _domainController = string.IsNullOrWhiteSpace(domainController) ? null : domainController;
        _requestedDomain = string.IsNullOrWhiteSpace(domain) ? null : domain;
    }

    public IReadOnlyList<string> QueryLog
    {
        get
        {
            lock (_sync)
                return _queryLog.ToArray();
        }
    }

    public static IReadOnlyList<string> QueryCatalog { get; } =
    [
        "Base: <domain DN> | Filter: (objectClass=domainDNS)",
        "Base: <domain DN> | Filter: (&(objectCategory=computer)(primaryGroupID=516))",
        "Base: <configuration DN> | Filter: (&(objectClass=crossRef)(nCName=<domain DN>))",
        "Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user))",
        "Base: <domain DN> | Filter: (objectCategory=computer)",
        "Base: <schema DN> | Filter: (&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)))",
        "Base: <domain DN> | Filter: (objectSid=<well-known SID bytes>)",
        $"Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user)(memberOf:{MatchingRuleInChain}:=<group DN>))",
        "Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user)(sAMAccountName=krbtgt))",
        "Base: <domain DN> | Filter: (|(objectClass=domainDNS)(objectClass=organizationalUnit)(distinguishedName=CN=Users,<domain DN>)(distinguishedName=CN=Computers,<domain DN>)) | SecurityMasks: Dacl",
        "Base: CN=AdminSDHolder,CN=System,<domain DN> | Filter: (objectClass=container) | SecurityMasks: Dacl",
        "Base: <user DN> | Filter: (objectClass=user) | SecurityMasks: Dacl",
        "Base: <domain DN> | Filter: (objectSid=<trustee SID bytes>)",
        $"Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user)(memberOf:{MatchingRuleInChain}:=<trustee group DN>))",
    ];

    public DomainInfo GetDomain()
    {
        if (_domain is not null)
            return _domain;
        EnsureNamingContexts();
        var domainRows = Search(_baseDn!, "(objectClass=domainDNS)", SearchScope.Base,
            ["objectSid", "msDS-Behavior-Version"], MapPropertyBag);
        if (domainRows is null || domainRows.Count == 0)
            throw new DirectoryUnavailableException("The domain naming context could not be read.");
        var properties = domainRows[0];
        var dcCount = Search(_baseDn!, "(&(objectCategory=computer)(primaryGroupID=516))", SearchScope.Subtree,
            ["distinguishedName"], _ => true)?.Count;
        string? netBios = null;
        if (!string.IsNullOrEmpty(_configurationDn))
        {
            var filter = $"(&(objectClass=crossRef)(nCName={EscapeFilter(_baseDn!)}))";
            netBios = Search(_configurationDn, filter, SearchScope.Subtree, ["nETBIOSName"],
                result => StringValue(result, "nETBIOSName"))?.FirstOrDefault(value => value is not null);
        }
        string? domainSid = null;
        var sidBytes = BytesValue(properties, "objectSid");
        if (sidBytes is not null)
        {
            try { domainSid = new SecurityIdentifier(sidBytes, 0).Value; }
            catch (ArgumentException) { }
        }
        _domain = new DomainInfo(DnToDomain(_baseDn!), netBios, FunctionalLevel(IntValue(properties, "msDS-Behavior-Version")), dcCount)
        {
            Sid = domainSid,
        };
        return _domain;
    }

    public IReadOnlyList<ScanUser>? GetUsers()
    {
        if (_usersAttempted)
            return _users;
        _usersAttempted = true;
        EnsureNamingContexts();
        _users = Search(_baseDn!, "(&(objectCategory=person)(objectClass=user))", SearchScope.Subtree, UserAttributes, MapUser);
        return _users;
    }

    public IReadOnlyList<ScanComputer>? GetComputers()
    {
        if (_computersAttempted)
            return _computers;
        _computersAttempted = true;
        EnsureNamingContexts();
        _computers = Search(_baseDn!, "(objectCategory=computer)", SearchScope.Subtree, ComputerAttributes, MapComputer);
        return _computers;
    }

    public bool? IsLapsSchemaPresent()
    {
        if (_lapsSchemaAttempted)
            return _lapsSchemaPresent;
        _lapsSchemaAttempted = true;
        EnsureNamingContexts();
        if (string.IsNullOrWhiteSpace(_schemaDn))
            return _lapsSchemaPresent = null;
        const string filter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)))";
        var attributes = Search(_schemaDn, filter, SearchScope.Subtree, ["lDAPDisplayName"],
            result => StringValue(result, "lDAPDisplayName"));
        return _lapsSchemaPresent = attributes is null ? null : attributes.Count > 0;
    }

    public IReadOnlySet<string>? GetPrivilegedUserDns()
    {
        if (_privilegedAttempted)
            return _privileged;
        _privilegedAttempted = true;
        _privileged = ReadNestedGroupMembers(PrivilegedRids);
        return _privileged;
    }

    public IReadOnlySet<string>? GetProtectedUserDns()
    {
        if (_protectedAttempted)
            return _protected;
        _protectedAttempted = true;
        _protected = ReadNestedGroupMembers([525]);
        return _protected;
    }

    public DomainPasswordPolicy? GetDefaultPasswordPolicy()
    {
        if (_policyAttempted)
            return _policy;
        _policyAttempted = true;
        EnsureNamingContexts();
        var rows = Search(_baseDn!, "(objectClass=domainDNS)", SearchScope.Base,
            ["minPwdLength", "lockoutThreshold", "pwdProperties", "maxPwdAge"], MapPropertyBag);
        if (rows is null || rows.Count == 0)
            return null;
        var values = rows[0];
        var pwdProperties = IntValue(values, "pwdProperties");
        _policy = new DomainPasswordPolicy(
            IntValue(values, "minPwdLength"),
            IntValue(values, "lockoutThreshold"),
            pwdProperties is null ? null : (pwdProperties.Value & 1) != 0,
            NegativeInterval(values, "maxPwdAge"));
        return _policy;
    }

    public ScanUser? GetKrbtgt()
    {
        if (_krbtgtAttempted)
            return _krbtgt;
        _krbtgtAttempted = true;
        EnsureNamingContexts();
        _krbtgt = Search(_baseDn!, "(&(objectCategory=person)(objectClass=user)(sAMAccountName=krbtgt))", SearchScope.Subtree,
            UserAttributes, MapUser)?.FirstOrDefault();
        return _krbtgt;
    }

    public IReadOnlyList<(string Dn, ScanAcl Acl)>? GetContainerAcls()
    {
        if (_containerAclsAttempted)
            return _containerAcls;
        _containerAclsAttempted = true;
        EnsureNamingContexts();
        var usersDn = $"CN=Users,{_baseDn}";
        var computersDn = $"CN=Computers,{_baseDn}";
        var filter = $"(|(objectClass=domainDNS)(objectClass=organizationalUnit)" +
            $"(distinguishedName={EscapeFilter(usersDn)})(distinguishedName={EscapeFilter(computersDn)}))";
        var rows = Search(_baseDn!, filter, SearchScope.Subtree,
            ["distinguishedName", "nTSecurityDescriptor"],
            result => (Dn: StringValue(result, "distinguishedName"), Descriptor: BytesValue(result, "nTSecurityDescriptor")),
            SecurityMasks.Dacl);
        if (rows is null)
            return null;
        var parsed = new List<(string Dn, ScanAcl Acl)>();
        foreach (var row in rows)
        {
            var acl = ParseAcl(row.Descriptor);
            if (string.IsNullOrWhiteSpace(row.Dn) || acl is null)
                return null;
            parsed.Add((row.Dn, acl));
        }
        var required = new[] { _baseDn!, usersDn, computersDn };
        if (required.Any(dn => !parsed.Any(item => item.Dn.Equals(dn, StringComparison.OrdinalIgnoreCase))))
            return null;
        _containerAcls = parsed;
        return _containerAcls;
    }

    public ScanAcl? GetAdminSdHolderAcl()
    {
        if (_adminSdHolderAclAttempted)
            return _adminSdHolderAcl;
        _adminSdHolderAclAttempted = true;
        EnsureNamingContexts();
        _adminSdHolderAcl = ReadObjectAcl($"CN=AdminSDHolder,CN=System,{_baseDn}", "(objectClass=container)");
        return _adminSdHolderAcl;
    }

    public ScanAcl? GetUserAcl(string dn)
    {
        lock (_sync)
        {
            if (_userAcls.TryGetValue(dn, out var cached))
                return cached;
        }
        var acl = ReadObjectAcl(dn, "(objectClass=user)");
        lock (_sync)
            _userAcls[dn] = acl;
        return acl;
    }

    public string? ResolveTrusteeName(string sid)
    {
        if (WellKnownTrusteeNames.TryGetValue(sid, out var name))
            return name;
        var lookup = LookupPrincipal(sid);
        return lookup is null ? null : lookup.Name ?? sid;
    }

    public string ResolveTrusteeKind(string sid)
    {
        var lookup = LookupPrincipal(sid);
        if (lookup?.IsGroup == true)
            return "Group";
        if (lookup?.IsServiceAccount == true)
            return "Service account";
        return lookup?.Exists == true ? "User" : "Account";
    }

    public IReadOnlySet<string>? GetNestedMemberDnsOfSid(string sid)
    {
        lock (_sync)
        {
            if (_principalMembers.TryGetValue(sid, out var cached))
                return cached;
        }

        IReadOnlySet<string>? members;
        if (sid.Equals("S-1-1-0", StringComparison.OrdinalIgnoreCase) ||
            sid.Equals("S-1-5-11", StringComparison.OrdinalIgnoreCase) ||
            GetDomain().Sid is string domainSid && sid.Equals($"{domainSid}-513", StringComparison.OrdinalIgnoreCase))
        {
            members = GetUsers()?.Select(user => user.DistinguishedName)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        else
        {
            var principal = LookupPrincipal(sid);
            if (principal is null)
                members = null;
            else if (!principal.Exists)
                members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            else if (!principal.IsGroup)
                members = principal.Dn is null
                    ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>([principal.Dn], StringComparer.OrdinalIgnoreCase);
            else if (principal.Dn is null)
                members = null;
            else
            {
                var filter = $"(&(objectCategory=person)(objectClass=user)(memberOf:{MatchingRuleInChain}:={EscapeFilter(principal.Dn)}))";
                var nested = Search(_baseDn!, filter, SearchScope.Subtree, ["distinguishedName"],
                    result => StringValue(result, "distinguishedName"));
                members = nested?.OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
            }
        }

        lock (_sync)
            _principalMembers[sid] = members;
        return members;
    }

    public bool IsGroupSid(string sid)
    {
        if (sid.Equals("S-1-1-0", StringComparison.OrdinalIgnoreCase) ||
            sid.Equals("S-1-5-11", StringComparison.OrdinalIgnoreCase))
            return true;
        return LookupPrincipal(sid)?.IsGroup == true;
    }

    private ScanAcl? ReadObjectAcl(string dn, string filter)
    {
        var descriptors = Search(dn, filter, SearchScope.Base, ["nTSecurityDescriptor"],
            result => BytesValue(result, "nTSecurityDescriptor"), SecurityMasks.Dacl);
        return descriptors is { Count: 1 } ? ParseAcl(descriptors[0]) : null;
    }

    private PrincipalLookup? LookupPrincipal(string sid)
    {
        lock (_sync)
        {
            if (_principalLookups.TryGetValue(sid, out var cached))
                return cached;
        }

        PrincipalLookup? lookup;
        try
        {
            var identifier = new SecurityIdentifier(sid);
            var bytes = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(bytes, 0);
            EnsureNamingContexts();
            var rows = Search(_baseDn!, $"(objectSid={EscapeBinary(bytes)})", SearchScope.Subtree,
                ["distinguishedName", "sAMAccountName", "objectClass"], result => new PrincipalLookup(
                    true,
                    StringValue(result, "distinguishedName"),
                    StringValue(result, "sAMAccountName"),
                    StringValues(result, "objectClass").Any(value => value.Equals("group", StringComparison.OrdinalIgnoreCase)),
                    StringValues(result, "objectClass").Any(value => value.Equals("msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase) || value.Equals("msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase))));
            lookup = rows is null ? null : rows.FirstOrDefault() ?? new PrincipalLookup(false, null, null, false, false);
        }
        catch (ArgumentException)
        {
            lookup = new PrincipalLookup(false, null, null, false, false);
        }

        lock (_sync)
            _principalLookups[sid] = lookup;
        return lookup;
    }

    private static ScanAcl? ParseAcl(byte[]? descriptor)
    {
        if (descriptor is null)
            return null;
        try
        {
            var security = new ActiveDirectorySecurity();
            security.SetSecurityDescriptorBinaryForm(descriptor);
            var entries = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .OfType<ActiveDirectoryAccessRule>()
                .Select(rule => new AclEntry
                {
                    TrusteeSid = rule.IdentityReference.Value,
                    Allow = rule.AccessControlType == AccessControlType.Allow,
                    AccessMask = unchecked((int)rule.ActiveDirectoryRights),
                    ObjectType = rule.ObjectType == Guid.Empty ? null : rule.ObjectType,
                    InheritedObjectType = rule.InheritedObjectType == Guid.Empty ? null : rule.InheritedObjectType,
                    ContainerInherit = (rule.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0,
                    InheritOnly = (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0,
                    NoPropagateInherit = (rule.PropagationFlags & PropagationFlags.NoPropagateInherit) != 0,
                    IsInherited = rule.IsInherited,
                }).ToArray();
            return new ScanAcl { Entries = entries, DaclProtected = security.AreAccessRulesProtected };
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or PlatformNotSupportedException)
        {
            return null;
        }
    }

    private IReadOnlySet<string>? ReadNestedGroupMembers(IEnumerable<int> rids)
    {
        EnsureNamingContexts();
        var domainSid = Search(_baseDn!, "(objectClass=domainDNS)", SearchScope.Base, ["objectSid"],
            result => BytesValue(result, "objectSid"))?.FirstOrDefault(value => value is not null);
        if (domainSid is null)
            return null;
        string sidText;
        try
        {
            sidText = new SecurityIdentifier(domainSid, 0).Value;
        }
        catch (ArgumentException)
        {
            return null;
        }

        var members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rid in rids)
        {
            var sid = new SecurityIdentifier(rid is 544 or 548 or 549 or 550 or 551 ? $"S-1-5-32-{rid}" : $"{sidText}-{rid}");
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            var group = Search(_baseDn!, $"(objectSid={EscapeBinary(bytes)})", SearchScope.Subtree,
                ["distinguishedName"], result => StringValue(result, "distinguishedName"));
            if (group is null)
                return null;
            var groupDn = group.FirstOrDefault(value => value is not null);
            if (groupDn is null)
                continue;
            var filter = $"(&(objectCategory=person)(objectClass=user)(memberOf:{MatchingRuleInChain}:={EscapeFilter(groupDn)}))";
            var nested = Search(_baseDn!, filter, SearchScope.Subtree, ["distinguishedName"],
                result => StringValue(result, "distinguishedName"));
            if (nested is null)
                return null;
            foreach (var dn in nested.OfType<string>())
                members.Add(dn);
        }
        return members;
    }

    private void EnsureNamingContexts()
    {
        if (_baseDn is not null)
            return;
        if (_requestedDomain is not null)
            _baseDn = string.Join(',', _requestedDomain.Split('.').Select(part => $"DC={part}"));
        try
        {
            using var root = new DirectoryEntry(PathFor("RootDSE"), null, null, SecureAuthentication);
            _baseDn ??= root.Properties["defaultNamingContext"].Value?.ToString();
            _configurationDn = root.Properties["configurationNamingContext"].Value?.ToString();
            _schemaDn = root.Properties["schemaNamingContext"].Value?.ToString();
        }
        catch (Exception exception) when (IsDirectoryFailure(exception))
        {
            throw new DirectoryUnavailableException("No Active Directory domain controller could be reached.", exception);
        }
        if (string.IsNullOrWhiteSpace(_baseDn))
            throw new DirectoryUnavailableException("The directory did not expose a default naming context.");
    }

    private IReadOnlyList<T>? Search<T>(string baseDn, string filter, SearchScope scope, IEnumerable<string> attributes, Func<SearchResult, T> map,
        SecurityMasks securityMasks = SecurityMasks.None)
    {
        lock (_sync)
            _queryLog.Add($"Base: {baseDn} | Filter: {filter}");
        try
        {
            using var root = new DirectoryEntry(PathFor(baseDn), null, null, SecureAuthentication);
            using var searcher = new DirectorySearcher(root)
            {
                Filter = filter,
                SearchScope = scope,
                PageSize = 1000,
                SizeLimit = 0,
                CacheResults = false,
                SecurityMasks = securityMasks,
            };
            foreach (var attribute in attributes)
                searcher.PropertiesToLoad.Add(attribute);
            using var results = searcher.FindAll();
            return results.Cast<SearchResult>().Select(map).ToArray();
        }
        catch (Exception exception) when (IsDirectoryFailure(exception))
        {
            return null;
        }
    }

    private string PathFor(string target) => _domainController is null ? $"LDAP://{target}" : $"LDAP://{_domainController}/{target}";

    private static AuthenticationTypes SecureAuthentication =>
        AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.Signing;

    private static ScanUser MapUser(SearchResult result)
    {
        var uac = IntValue(result, "userAccountControl");
        var pwdRaw = LongValue(result, "pwdLastSet");
        return new ScanUser
        {
            SamAccountName = StringValue(result, "sAMAccountName") ?? string.Empty,
            DistinguishedName = StringValue(result, "distinguishedName") ?? string.Empty,
            Enabled = uac is null || (uac.Value & Disabled) == 0,
            UserAccountControl = uac,
            LastLogonUtc = FileTime(result, "lastLogonTimestamp"),
            WhenCreatedUtc = GeneralizedTime(result, "whenCreated"),
            PwdLastSetUtc = pwdRaw is > 0 ? DateTime.FromFileTimeUtc(pwdRaw.Value) : null,
            MustChangePasswordAtNextLogon = pwdRaw == 0,
            AdminCount = IntValue(result, "adminCount"),
            ServicePrincipalNames = StringValues(result, "servicePrincipalName"),
            HasMailbox = HasProperty(result, "mail") || HasProperty(result, "msExchMailboxGuid"),
        };
    }

    private static ScanComputer MapComputer(SearchResult result)
    {
        var uac = IntValue(result, "userAccountControl");
        return new ScanComputer
        {
            SamAccountName = StringValue(result, "sAMAccountName") ?? string.Empty,
            DistinguishedName = StringValue(result, "distinguishedName") ?? string.Empty,
            Enabled = uac is null || (uac.Value & Disabled) == 0,
            OperatingSystem = StringValue(result, "operatingSystem"),
            UserAccountControl = uac,
            PrimaryGroupId = IntValue(result, "primaryGroupID"),
            HasLapsExpiry = HasProperty(result, "msLAPS-PasswordExpirationTime") || HasProperty(result, "ms-Mcs-AdmPwdExpirationTime"),
        };
    }

    private static SearchResult MapPropertyBag(SearchResult result) => result;
    private static bool HasProperty(SearchResult result, string name) => result.Properties.Contains(name) && result.Properties[name].Count > 0;
    private static string? StringValue(SearchResult result, string name) => HasProperty(result, name) ? result.Properties[name][0]?.ToString() : null;
    private static byte[]? BytesValue(SearchResult result, string name) => HasProperty(result, name) ? result.Properties[name][0] as byte[] : null;
    private static IReadOnlyList<string> StringValues(SearchResult result, string name) => HasProperty(result, name)
        ? result.Properties[name].Cast<object>().Select(value => value.ToString() ?? string.Empty).Where(value => value.Length > 0).ToArray()
        : Array.Empty<string>();
    private static int? IntValue(SearchResult result, string name)
    {
        var value = HasProperty(result, name) ? result.Properties[name][0] : null;
        if (value is null)
            return null;
        try { return Convert.ToInt32(value, CultureInfo.InvariantCulture); }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException) { return null; }
    }

    private static long? LongValue(SearchResult result, string name)
    {
        if (!HasProperty(result, name))
            return null;
        try { return Convert.ToInt64(result.Properties[name][0], CultureInfo.InvariantCulture); }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException) { return null; }
    }

    private static DateTime? FileTime(SearchResult result, string name)
    {
        var value = LongValue(result, name);
        if (value is null or <= 0)
            return null;
        try { return DateTime.FromFileTimeUtc(value.Value); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static DateTime? GeneralizedTime(SearchResult result, string name)
    {
        var text = StringValue(result, name);
        return DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value)
            ? value : null;
    }

    private static TimeSpan? NegativeInterval(SearchResult result, string name)
    {
        var value = LongValue(result, name);
        if (value is null || value == long.MinValue)
            return null;
        return TimeSpan.FromTicks(Math.Abs(value.Value));
    }

    private static string? FunctionalLevel(int? value) => value switch
    {
        0 => "Windows 2000",
        1 => "Windows Server 2003 interim",
        2 => "Windows Server 2003",
        3 => "Windows Server 2008",
        4 => "Windows Server 2008 R2",
        5 => "Windows Server 2012",
        6 => "Windows Server 2012 R2",
        7 => "Windows Server 2016 or later",
        _ => null,
    };

    private static string EscapeFilter(string value)
    {
        var output = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            output.Append(character switch
            {
                '\\' => "\\5c",
                '*' => "\\2a",
                '(' => "\\28",
                ')' => "\\29",
                '\0' => "\\00",
                _ => character.ToString(),
            });
        }
        return output.ToString();
    }

    private static string EscapeBinary(IEnumerable<byte> value) => string.Concat(value.Select(item => $"\\{item:x2}"));
    private static string DnToDomain(string dn) => string.Join('.', dn.Split(',').Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)).Select(part => part[3..]));
    private static bool IsDirectoryFailure(Exception exception) => exception is System.Runtime.InteropServices.COMException or DirectoryServicesCOMException or InvalidOperationException;

    private static IReadOnlyDictionary<string, string> WellKnownTrusteeNames { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["S-1-1-0"] = "Everyone",
            ["S-1-3-0"] = "CREATOR OWNER",
            ["S-1-5-9"] = "Enterprise Domain Controllers",
            ["S-1-5-10"] = "SELF",
            ["S-1-5-11"] = "Authenticated Users",
            ["S-1-5-18"] = "SYSTEM",
            ["S-1-5-32-544"] = "Administrators",
            ["S-1-5-32-548"] = "Account Operators",
        };

    private sealed record PrincipalLookup(bool Exists, string? Dn, string? Name, bool IsGroup, bool IsServiceAccount);

    [GeneratedRegex(@"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")]
    private static partial Regex HostName();

    [GeneratedRegex(@"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")]
    private static partial Regex DomainName();
}
