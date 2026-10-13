using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class OperatorExposureCheck : ICheck
{
    private readonly BlastRadiusAnalysis _analysis;

    public OperatorExposureCheck() : this(new BlastRadiusAnalysis()) { }

    internal OperatorExposureCheck(BlastRadiusAnalysis analysis) => _analysis = analysis;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "A delegated operator who can be reset by another delegate is a stepping stone: taking over that account also inherits its full password-reset reach.";
        const string fix = "1. Put helpdesk operator accounts in a protected administrative OU or Protected Users where compatible. 2. Remove those accounts from delegated reset scope with ADUC Delegation of Control or dsacls. 3. Use separate named operator accounts.";
        const string insurer = "Are helpdesk accounts themselves protected from reset by other helpdesk accounts?";
        const string hint = "Velauth: caller verification before any reset";
        var result = _analysis.Get(directory);
        if (result.Error is not null)
            return CheckSupport.NotVisible(4, "Delegated operators exposed to reset", "Helpdesk blast radius", Severity.High,
                why, fix, result.Error, insurer, hint);
        return CheckSupport.Result(4, "Delegated operators exposed to reset", "Helpdesk blast radius", Severity.High,
            result.OperatorExposureUsers, why, fix, insurer, hint);
    }
}
