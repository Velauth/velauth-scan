using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class UnconstrainedDelegationCheck : ICheck
{
    private const int TrustedForDelegation = 0x80000;
    private const int DomainControllerPrimaryGroup = 516;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Unconstrained delegation can place reusable Kerberos credentials on the delegated host or account. Domain controllers are excluded because AD marks them by design.";
        const string fix = "1. Identify the service dependency. 2. Replace unconstrained delegation with constrained or resource-based constrained delegation. 3. Clear Trust this user or computer for delegation to any service.";
        var users = directory.GetUsers();
        var computers = directory.GetComputers();
        if (users is null || computers is null)
            return CheckSupport.NotVisible(18, "Unconstrained delegation", "Attack paths", Severity.High, why, fix,
                "The user or computer query could not be read.");
        var unknown = users.Any(user => user.Enabled && user.UserAccountControl is null) ||
            computers.Any(computer => computer.Enabled && (computer.UserAccountControl is null ||
                (computer.UserAccountControl is int value && (value & TrustedForDelegation) != 0 && computer.PrimaryGroupId is null)));
        var matches = users.Where(user => user.Enabled && user.UserAccountControl is int uac && (uac & TrustedForDelegation) != 0)
            .Select(CheckSupport.Name)
            .Concat(computers.Where(computer => computer.Enabled && computer.PrimaryGroupId != DomainControllerPrimaryGroup &&
                    computer.UserAccountControl is int uac && (uac & TrustedForDelegation) != 0)
                .Select(CheckSupport.Name)).ToArray();
        if (matches.Length == 0 && unknown)
            return CheckSupport.NotVisible(18, "Unconstrained delegation", "Attack paths", Severity.High, why, fix,
                "One or more delegation or primaryGroupId values could not be read.");
        return CheckSupport.Result(18, "Unconstrained delegation", "Attack paths", Severity.High, matches, why, fix);
    }
}
