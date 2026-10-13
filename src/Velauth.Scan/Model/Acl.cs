namespace Velauth.Scan.Model;

public sealed record AclEntry
{
    public required string TrusteeSid { get; init; }
    public required bool Allow { get; init; }
    public required int AccessMask { get; init; }
    public Guid? ObjectType { get; init; }
    public Guid? InheritedObjectType { get; init; }
    public required bool ContainerInherit { get; init; }
    public required bool InheritOnly { get; init; }
    public required bool NoPropagateInherit { get; init; }
    public required bool IsInherited { get; init; }
}

public sealed record ScanAcl
{
    public required IReadOnlyList<AclEntry> Entries { get; init; }
    public required bool DaclProtected { get; init; }
}

public sealed record PrincipalReach(
    string Name,
    string Kind,
    int ReachableUsers,
    int Members);

public sealed record ResetBlastRadius
{
    public required int ResettableEnabledUsers { get; init; }
    public required int EnabledUsers { get; init; }
    public required int DelegatedPrincipals { get; init; }
    public required int DelegatedPeople { get; init; }
    public required IReadOnlyList<PrincipalReach> TopPrincipals { get; init; }
}
