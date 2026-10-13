using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class DefaultPasswordPolicyCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Baseline: minimum length 12 or more, lockout threshold from 1 to 10, and complexity enabled or minimum length 14 or more. This checks the default domain policy only.";
        const string fix = "1. Open Group Policy Management. 2. Edit the domain password and account lockout policy. 3. Set the baseline values, test, and communicate the change.";
        var policy = directory.GetDefaultPasswordPolicy();
        if (policy is null || policy.MinimumPasswordLength is null || policy.LockoutThreshold is null || policy.ComplexityEnabled is null)
            return CheckSupport.NotVisible(20, "Default domain password policy", "Directory hygiene", Severity.Medium, why, fix,
                "The default domain password policy or one of its required attributes could not be read.", "Does the default domain password policy meet the stated baseline?");

        var results = new List<string>();
        if (policy.MinimumPasswordLength < 12)
            results.Add($"Minimum password length is {policy.MinimumPasswordLength}, baseline is 12 or more");
        if (policy.LockoutThreshold is < 1 or > 10)
            results.Add($"Lockout threshold is {policy.LockoutThreshold}, baseline is 1 to 10");
        if (!policy.ComplexityEnabled.Value && policy.MinimumPasswordLength < 14)
            results.Add("Complexity is disabled and minimum password length is below the 14-character alternative");
        var detail = $" Minimum length: {(policy.MinimumPasswordLength >= 12 ? "Pass" : "Fail")} ({policy.MinimumPasswordLength})." +
            $" Lockout threshold: {(policy.LockoutThreshold is >= 1 and <= 10 ? "Pass" : "Fail")} ({policy.LockoutThreshold})." +
            $" Complexity or 14-character alternative: {(policy.ComplexityEnabled.Value || policy.MinimumPasswordLength >= 14 ? "Pass" : "Fail")}.";
        return CheckSupport.Result(20, "Default domain password policy", "Directory hygiene", Severity.Medium, results, why + detail, fix,
            "Does the default domain password policy meet the stated baseline?");
    }
}
