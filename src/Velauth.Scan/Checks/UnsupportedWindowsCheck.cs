using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public sealed class UnsupportedWindowsCheck : ICheck
{
    public Finding Run(IScanDirectory directory, DateTime nowUtc)
    {
        const string why = "Unsupported Windows releases no longer receive ordinary security fixes. Active Directory cannot tell whether Windows 10 has Extended Security Updates.";
        const string fix = "1. Confirm the operating system on each device. 2. Check for Extended Security Updates where applicable. 3. Upgrade, isolate, or retire unsupported devices.";
        var computers = directory.GetComputers();
        if (computers is null)
            return CheckSupport.NotVisible(15, "Computers on unsupported Windows versions", "Directory hygiene", Severity.Medium, why, fix,
                "The computer query could not be read.", "Are all Windows devices on supported releases?", "Velauth: Needs attention, Unsupported operating systems");
        var matches = computers.Where(computer => computer.Enabled && OsSupportClassifier.Classify(computer.OperatingSystem, nowUtc).Status == OsSupportStatus.Unsupported)
            .Select(computer => $"{CheckSupport.Name(computer)} ({computer.OperatingSystem})").ToArray();
        if (matches.Length == 0 && computers.Any(computer => computer.UserAccountControl is null))
            return CheckSupport.NotVisible(15, "Computers on unsupported Windows versions", "Directory hygiene", Severity.Medium, why, fix,
                "userAccountControl could not be read for one or more computers.", "Are all Windows devices on supported releases?", "Velauth: Needs attention, Unsupported operating systems");
        return CheckSupport.Result(15, "Computers on unsupported Windows versions", "Directory hygiene", Severity.Medium, matches, why, fix,
            "Are all Windows devices on supported releases?", "Velauth: Needs attention, Unsupported operating systems");
    }
}
