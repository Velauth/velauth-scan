using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class ResettablePrivilegedCheck : ICheck
{
    private readonly BlastRadiusAnalysis _analysis;

    public ResettablePrivilegedCheck() : this(new BlastRadiusAnalysis()) { }

    internal ResettablePrivilegedCheck(BlastRadiusAnalysis analysis) => _analysis = analysis;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "A privileged user's unprotected DACL can inherit helpdesk Reset Password delegation, turning a helpdesk compromise into administrative control.";
        const string fix = "1. Remove the privileged account from the delegated OU or narrow the delegation with ADUC or dsacls. 2. Restore the intended protected DACL and adminCount state. 3. Review AdminSDHolder and privileged group membership.";
        const string insurer = "Can helpdesk staff reset administrator passwords?";
        const string hint = "Velauth: approvals and Tier-0 guard";
        var result = _analysis.Get(directory);
        var reason = result.Error ?? result.PrivilegedError;
        if (reason is not null)
            return CheckSupport.NotVisible(2, "Privileged accounts exposed to delegated reset", "Helpdesk blast radius", Severity.Critical,
                why, fix, reason, insurer, hint);
        return CheckSupport.Result(2, "Privileged accounts exposed to delegated reset", "Helpdesk blast radius", Severity.Critical,
            result.ResettablePrivilegedUsers, why, fix, insurer, hint);
    }
}
