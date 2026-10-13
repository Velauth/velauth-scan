using Velauth.Scan.Checks;
using Velauth.Scan.Directory;

namespace Velauth.Scan;

public static class ScanRunner
{
    private static ICheck[] CreateChecks(BlastRadiusAnalysis analysis) =>
    [
        new ResetDelegationCheck(analysis),
        new ResettablePrivilegedCheck(analysis),
        new AdminSdHolderCheck(),
        new OperatorExposureCheck(analysis),
        new PrivilegedMemberCountCheck(),
        new PrivilegedPasswordCheck(),
        new PrivilegedProtectionCheck(),
        new PrivilegedDailyUseCheck(),
        new OrphanedAdminCountCheck(),
        new KrbtgtPasswordAgeCheck(),
        new StaleSignInCheck(),
        new NeverSignedInCheck(),
        new NonServicePasswordNeverExpiresCheck(),
        new WeakPasswordFlagsCheck(),
        new UnsupportedWindowsCheck(),
        new KerberoastableAccountsCheck(),
        new AsRepRoastableAccountsCheck(),
        new UnconstrainedDelegationCheck(),
        new LapsCoverageCheck(),
        new DefaultPasswordPolicyCheck(),
    ];

    public static ScanResult Run(IScanDirectory directory, DateTime nowUtc)
    {
        var domain = directory.GetDomain();
        var analysis = new BlastRadiusAnalysis();
        var findings = CreateChecks(analysis).Select(check => check.Run(directory, nowUtc)).ToArray();
        return ScanScoring.Create(domain.Name, nowUtc, findings, directory.QueryLog);
    }
}
