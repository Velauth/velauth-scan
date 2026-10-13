using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class ResetDelegationCheck : ICheck
{
    private readonly BlastRadiusAnalysis _analysis;

    public ResetDelegationCheck() : this(new BlastRadiusAnalysis()) { }

    internal ResetDelegationCheck(BlastRadiusAnalysis analysis) => _analysis = analysis;

    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string title = "Password reset delegation blast radius";
        const string category = "Helpdesk blast radius";
        const string fix = "1. Use dsacls or ADUC Delegation of Control to remove broad reset rights. 2. Scope Reset Password to the smallest reviewed helpdesk group and OU. 3. Remove Authenticated Users, Everyone, Domain Users, and unnecessary Account Operators delegation.";
        const string insurer = "Is password reset delegation limited to a small, reviewed group?";
        const string hint = "Velauth: caller verification before any reset";
        var result = _analysis.Get(directory);
        const string assumption = "Container inheritance is assumed for non-privileged users unless adminCount is 1; adminCount=1 users are excluded here and reviewed by the privileged checks.";
        if (result.Error is not null)
        {
            return CheckSupport.NotVisible(1, title, category, Severity.High,
                "Password reset delegation determines how many accounts a helpdesk identity can take over. " + assumption,
                fix, result.Error, insurer, hint);
        }

        var blast = result.BlastRadius!;
        var share = blast.EnabledUsers == 0 ? 0m : blast.ResettableEnabledUsers * 100m / blast.EnabledUsers;
        var fail = blast.ResettableEnabledUsers > 0 && (result.HasBroadTrustee || share > 25m);
        var severity = result.HasCriticalBroadTrustee ? Severity.Critical : Severity.High;
        var summary = $"Delegated to {blast.DelegatedPeople} people, scope {blast.ResettableEnabledUsers} accounts. {assumption}";
        return new Finding
        {
            Id = 1,
            Title = title,
            Category = category,
            Severity = severity,
            Status = fail ? CheckStatus.Fail : CheckStatus.Pass,
            Count = blast.ResettableEnabledUsers,
            Accounts = result.ResettableUsers.Take(CheckSupport.AccountLimit).ToArray(),
            AccountsTotal = result.ResettableUsers.Count,
            Why = "A caller who convinces a delegated operator to reset a password can take over every account in that operator's scope. " + summary,
            Fix = fix,
            InsurerQuestion = insurer,
            VelauthHint = hint,
            Details = blast,
        };
    }
}
