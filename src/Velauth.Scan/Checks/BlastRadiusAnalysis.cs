using System.Runtime.CompilerServices;
using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class BlastRadiusAnalysis
{
    private readonly ConditionalWeakTable<IScanDirectory, Holder> _cache = new();

    internal BlastRadiusSnapshot Get(IScanDirectory directory) =>
        _cache.GetValue(directory, static value => new Holder(Analyze(value))).Value;

    private static BlastRadiusSnapshot Analyze(IScanDirectory directory)
    {
        var users = directory.GetUsers();
        var containers = directory.GetContainerAcls();
        if (users is null || containers is null)
        {
            return BlastRadiusSnapshot.NotVisible(
                "Container ACLs or users could not be read. The blast radius is unknown, not zero.");
        }

        var domain = directory.GetDomain();
        if (domain.Sid is null)
            return BlastRadiusSnapshot.NotVisible("The domain SID could not be read, so expected domain trustees cannot be identified safely.");
        if (users.Any(user => user.UserAccountControl is null))
            return BlastRadiusSnapshot.NotVisible("The enabled state of one or more users could not be read. The blast radius is unknown, not zero.");
        var usersByDn = CheckSupport.UsersByDn(users);
        var effective = ResetRights.EffectiveContainerGrants(containers, users)
            .Where(pair => !ResetRights.IsIgnoredTrustee(pair.TrusteeSid, domain.Sid))
            .ToArray();
        var trusteeSids = effective.Select(pair => pair.TrusteeSid)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var membersBySid = new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase);
        var namesBySid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var kindBySid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var sid in trusteeSids)
        {
            var members = directory.GetNestedMemberDnsOfSid(sid);
            if (members is null)
            {
                return BlastRadiusSnapshot.NotVisible(
                    $"Nested membership for delegated trustee {sid} could not be read. The blast radius is unknown, not zero.");
            }
            membersBySid[sid] = members;
            namesBySid[sid] = directory.ResolveTrusteeName(sid) ?? sid;
            kindBySid[sid] = directory.ResolveTrusteeKind(sid);
        }

        var enabledUsers = users.Where(user => user.Enabled).ToArray();
        var resettablePairs = effective.Where(pair =>
            usersByDn.TryGetValue(pair.UserDn, out var user) && user.Enabled && user.AdminCount != 1).ToArray();
        var resettableDns = resettablePairs.Select(pair => pair.UserDn)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var activeTrustees = resettablePairs.Select(pair => pair.TrusteeSid)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var delegatedPeopleDns = activeTrustees.SelectMany(sid => membersBySid[sid])
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var topPrincipals = activeTrustees.Select(sid => new PrincipalReach(
                namesBySid[sid],
                kindBySid[sid],
                resettablePairs.Where(pair => pair.TrusteeSid.Equals(sid, StringComparison.OrdinalIgnoreCase))
                    .Select(pair => pair.UserDn).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                membersBySid[sid].Count))
            .OrderByDescending(principal => principal.ReachableUsers)
            .ThenBy(principal => principal.Name, StringComparer.OrdinalIgnoreCase)
            .Take(10).ToArray();
        var blastRadius = new ResetBlastRadius
        {
            ResettableEnabledUsers = resettableDns.Count,
            EnabledUsers = enabledUsers.Length,
            DelegatedPrincipals = activeTrustees.Length,
            DelegatedPeople = delegatedPeopleDns.Count,
            TopPrincipals = topPrincipals,
        };

        string? privilegedError = null;
        var resettablePrivileged = new List<string>();
        var privilegedDns = directory.GetPrivilegedUserDns();
        if (privilegedDns is null)
        {
            privilegedError = "Privileged membership could not be read.";
        }
        else
        {
            var delegatedPrivileged = privilegedDns.Where(dn => effective.Any(pair =>
                    pair.UserDn.Equals(dn, StringComparison.OrdinalIgnoreCase)))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (delegatedPrivileged.Length > 500)
            {
                privilegedError = "More than 500 privileged users are in delegated scopes, so the protected-DACL read cap was reached.";
            }
            else
            {
                foreach (var dn in delegatedPrivileged)
                {
                    var acl = directory.GetUserAcl(dn);
                    if (acl is null)
                    {
                        privilegedError = $"The DACL for privileged user {dn} could not be read.";
                        resettablePrivileged.Clear();
                        break;
                    }
                    if (!acl.DaclProtected)
                        resettablePrivileged.Add(usersByDn.TryGetValue(dn, out var user) ? CheckSupport.Name(user) : dn);
                }
            }
        }

        var operatorExposure = delegatedPeopleDns.Intersect(resettableDns, StringComparer.OrdinalIgnoreCase)
            .Select(dn => usersByDn.TryGetValue(dn, out var user) ? CheckSupport.Name(user) : dn)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
        var resettableNames = resettableDns.Select(dn => usersByDn.TryGetValue(dn, out var user) ? CheckSupport.Name(user) : dn)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();

        return new BlastRadiusSnapshot
        {
            BlastRadius = blastRadius,
            ResettableUsers = resettableNames,
            ResettablePrivilegedUsers = resettablePrivileged.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray(),
            PrivilegedError = privilegedError,
            OperatorExposureUsers = operatorExposure,
            HasBroadTrustee = activeTrustees.Any(sid => ResetRights.IsBroadTrustee(sid, domain.Sid)),
            HasCriticalBroadTrustee = activeTrustees.Any(sid => ResetRights.IsCriticalBroadTrustee(sid, domain.Sid)),
        };
    }

    private sealed record Holder(BlastRadiusSnapshot Value);
}

internal sealed record BlastRadiusSnapshot
{
    internal string? Error { get; init; }
    internal ResetBlastRadius? BlastRadius { get; init; }
    internal IReadOnlyList<string> ResettableUsers { get; init; } = Array.Empty<string>();
    internal IReadOnlyList<string> ResettablePrivilegedUsers { get; init; } = Array.Empty<string>();
    internal string? PrivilegedError { get; init; }
    internal IReadOnlyList<string> OperatorExposureUsers { get; init; } = Array.Empty<string>();
    internal bool HasBroadTrustee { get; init; }
    internal bool HasCriticalBroadTrustee { get; init; }

    internal static BlastRadiusSnapshot NotVisible(string reason) => new() { Error = reason };
}
