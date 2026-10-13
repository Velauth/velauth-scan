namespace Velauth.Scan.Model;

public sealed record DomainInfo(
    string Name,
    string? NetBiosName,
    string? FunctionalLevel,
    int? DomainControllerCount)
{
    public string? Sid { get; init; }
}

public sealed record ScanUser
{
    public required string SamAccountName { get; init; }
    public required string DistinguishedName { get; init; }
    public required bool Enabled { get; init; }
    public int? UserAccountControl { get; init; }
    public DateTime? LastLogonUtc { get; init; }
    public DateTime? WhenCreatedUtc { get; init; }
    public DateTime? PwdLastSetUtc { get; init; }
    public bool MustChangePasswordAtNextLogon { get; init; }
    public int? AdminCount { get; init; }
    public IReadOnlyList<string>? ServicePrincipalNames { get; init; }
    public bool? HasMailbox { get; init; }
}

public sealed record ScanComputer
{
    public required string SamAccountName { get; init; }
    public required string DistinguishedName { get; init; }
    public required bool Enabled { get; init; }
    public string? OperatingSystem { get; init; }
    public int? UserAccountControl { get; init; }
    public int? PrimaryGroupId { get; init; }
    public bool? HasLapsExpiry { get; init; }
}

public sealed record DomainPasswordPolicy(
    int? MinimumPasswordLength,
    int? LockoutThreshold,
    bool? ComplexityEnabled,
    TimeSpan? MaximumPasswordAge);
