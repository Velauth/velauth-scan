namespace Velauth.Scan.Model;

public sealed record Finding
{
    public required int Id { get; init; }
    public required string Title { get; init; }
    public required string Category { get; init; }
    public required Severity Severity { get; init; }
    public required CheckStatus Status { get; init; }
    public int? Count { get; init; }
    public required IReadOnlyList<string> Accounts { get; init; }
    public int? AccountsTotal { get; init; }
    public required string Why { get; init; }
    public required string Fix { get; init; }
    public string? InsurerQuestion { get; init; }
    public string? VelauthHint { get; init; }
    public string? NotVisibleReason { get; init; }
    public object? Details { get; init; }
}
