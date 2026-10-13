using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class LapsCoverageCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Without LAPS one stolen local admin password opens every machine with the same one.";
        const string fix = "Deploy Windows LAPS (built in since the April 2023 updates).";
        const string insurer = "Is local administrator password management (LAPS) in place?";
        const string hint = "Velauth: LAPS password retrieval with audit";
        var computers = directory.GetComputers();
        var schemaPresent = directory.IsLapsSchemaPresent();
        if (computers is null || schemaPresent is null)
            return CheckSupport.NotVisible(19, "LAPS coverage", "Attack paths", Severity.High, why, fix,
                "The computer query or LAPS schema query could not be read.", insurer, hint);

        var candidates = computers.Where(computer => computer.Enabled && computer.PrimaryGroupId != 516).ToArray();
        if (candidates.Any(computer => computer.PrimaryGroupId is null))
            return CheckSupport.NotVisible(19, "LAPS coverage", "Attack paths", Severity.High, why, fix,
                "primaryGroupID could not be read for one or more enabled computers.", insurer, hint);
        if (!schemaPresent.Value)
            return CheckSupport.Result(19, "LAPS coverage", "Attack paths", Severity.High,
                candidates.Select(CheckSupport.Name).ToArray(), "LAPS is not deployed", fix, insurer, hint);
        if (candidates.Any(computer => computer.HasLapsExpiry is null))
            return CheckSupport.NotVisible(19, "LAPS coverage", "Attack paths", Severity.High, why, fix,
                "The LAPS password expiry attribute could not be read for one or more enabled computers.", insurer, hint);

        var missing = candidates.Where(computer => computer.HasLapsExpiry == false).Select(CheckSupport.Name).ToArray();
        var severity = missing.Length == 0 ? Severity.Medium : missing.Length * 2 > candidates.Length ? Severity.High : Severity.Medium;
        return CheckSupport.Result(19, "LAPS coverage", "Attack paths", severity, missing, why, fix, insurer, hint);
    }
}
