using Velauth.Scan.Checks;
using Velauth.Scan.Model;

namespace Velauth.Tests.Scan;

public sealed class CheckTests
{
    private static readonly DateTime Now = new(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Check5_PassesAtFiveAndListsAccounts()
    {
        var fake = PrivilegedUsers(5);
        var finding = new PrivilegedMemberCountCheck().Run(fake, Now);
        Assert.Equal(CheckStatus.Pass, finding.Status);
        Assert.Equal(5, finding.Count);
        Assert.Equal(5, finding.Accounts.Count);
    }

    [Fact]
    public void Check5_FailsAboveFive()
    {
        Assert.Equal(CheckStatus.Fail, new PrivilegedMemberCountCheck().Run(PrivilegedUsers(6), Now).Status);
    }

    [Fact]
    public void Check5_IsNotVisibleWhenMembershipIsUnknown()
    {
        AssertNotVisible(new PrivilegedMemberCountCheck(), new FakeScanDirectory { PrivilegedUserDns = null });
    }

    [Fact]
    public void Check6_PassesAtExactly365Days()
    {
        var user = TestObjects.User(pwdLastSet: Now.AddDays(-365));
        Assert.Equal(CheckStatus.Pass, new PrivilegedPasswordCheck().Run(WithPrivileged(user), Now).Status);
    }

    [Fact]
    public void Check6_FailsForOldOrNeverExpiringPasswords()
    {
        var old = TestObjects.User("old", pwdLastSet: Now.AddDays(-366));
        var never = TestObjects.User("never", uac: 0x10000, pwdLastSet: Now);
        var fake = WithPrivileged(old, never);
        Assert.Equal(CheckStatus.Fail, new PrivilegedPasswordCheck().Run(fake, Now).Status);
        Assert.Equal(2, new PrivilegedPasswordCheck().Run(fake, Now).Count);
    }

    [Fact]
    public void Check6_DoesNotTurnUnreadablePasswordDataIntoZero()
    {
        AssertNotVisible(new PrivilegedPasswordCheck(), WithPrivileged(TestObjects.User(uac: null, pwdLastSet: null)));
    }

    [Fact]
    public void Check7_PassesForProtectedOrSensitiveAccounts()
    {
        var protectedUser = TestObjects.User("protected");
        var sensitive = TestObjects.User("sensitive", uac: 0x100000);
        var fake = WithPrivileged(protectedUser, sensitive);
        fake.ProtectedUserDns = new HashSet<string>([protectedUser.DistinguishedName], StringComparer.OrdinalIgnoreCase);
        Assert.Equal(CheckStatus.Pass, new PrivilegedProtectionCheck().Run(fake, Now).Status);
    }

    [Fact]
    public void Check7_FailsForAnUnprotectedAccount()
    {
        Assert.Equal(CheckStatus.Fail, new PrivilegedProtectionCheck().Run(WithPrivileged(TestObjects.User()), Now).Status);
    }

    [Fact]
    public void Check7_DoesNotTurnUnreadableUacIntoZero()
    {
        AssertNotVisible(new PrivilegedProtectionCheck(), WithPrivileged(TestObjects.User(uac: null)));
    }

    [Fact]
    public void Check8_FlagsMailboxOrRecentlyInteractivePrivilegedAccountsButExcludesKrbtgt()
    {
        var mailbox = TestObjects.User("admin-mail") with { HasMailbox = true };
        var recent = TestObjects.User("admin-recent", lastLogon: Now.AddDays(-14));
        var krbtgt = TestObjects.User("krbtgt") with { HasMailbox = true };
        var result = new PrivilegedDailyUseCheck().Run(WithPrivileged(mailbox, recent, krbtgt), Now);
        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Equal(["admin-mail", "admin-recent"], result.Accounts);
    }

    [Fact]
    public void Check8_IncludesBuiltInAdministratorOnlyForMailboxAndDoesNotHideUnreadableMailboxData()
    {
        var administrator = TestObjects.User("Administrator", lastLogon: Now) with { HasMailbox = false };
        Assert.Equal(CheckStatus.Pass, new PrivilegedDailyUseCheck().Run(WithPrivileged(administrator), Now).Status);
        var mailboxAdministrator = administrator with { HasMailbox = true };
        Assert.Equal(CheckStatus.Fail, new PrivilegedDailyUseCheck().Run(WithPrivileged(mailboxAdministrator), Now).Status);
        AssertNotVisible(new PrivilegedDailyUseCheck(), WithPrivileged(administrator with { HasMailbox = null }));
    }

    [Fact]
    public void Check9_PassesWithoutOrphansAndFailsWithOne()
    {
        Assert.Equal(CheckStatus.Pass, new OrphanedAdminCountCheck().Run(new FakeScanDirectory { Users = [TestObjects.User(adminCount: 0)] }, Now).Status);
        Assert.Equal(CheckStatus.Fail, new OrphanedAdminCountCheck().Run(new FakeScanDirectory { Users = [TestObjects.User(adminCount: 1)] }, Now).Status);
    }

    [Fact]
    public void Check9_DoesNotTurnUnreadableAdminCountIntoZero()
    {
        AssertNotVisible(new OrphanedAdminCountCheck(), new FakeScanDirectory { Users = [TestObjects.User(adminCount: null)] });
    }

    [Fact]
    public void Check9_PassesWhenOrdinaryUsersLackAdminCountButAPrivilegedAccountShowsIt()
    {
        var admin = TestObjects.User(adminCount: 1) with { DistinguishedName = "CN=Administrator,CN=Users,DC=example,DC=test" };
        var ordinary = TestObjects.User(adminCount: null) with { DistinguishedName = "CN=Pat,CN=Users,DC=example,DC=test" };
        var directory = new FakeScanDirectory
        {
            Users = [admin, ordinary],
            PrivilegedUserDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { admin.DistinguishedName },
        };
        Assert.Equal(CheckStatus.Pass, new OrphanedAdminCountCheck().Run(directory, Now).Status);
    }

    [Fact]
    public void Check9_DoesNotFlagKrbtgtButStillFlagsARealOrphan()
    {
        var admin = TestObjects.User(adminCount: 1) with { DistinguishedName = "CN=Administrator,CN=Users,DC=example,DC=test", SamAccountName = "Administrator" };
        var krbtgt = TestObjects.User(adminCount: 1) with { DistinguishedName = "CN=krbtgt,CN=Users,DC=example,DC=test", SamAccountName = "krbtgt" };
        var orphan = TestObjects.User(adminCount: 1) with { DistinguishedName = "CN=Old Admin,CN=Users,DC=example,DC=test", SamAccountName = "old.admin" };
        var privileged = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { admin.DistinguishedName };
        Assert.Equal(CheckStatus.Pass, new OrphanedAdminCountCheck().Run(new FakeScanDirectory { Users = [admin, krbtgt], PrivilegedUserDns = privileged }, Now).Status);
        var finding = new OrphanedAdminCountCheck().Run(new FakeScanDirectory { Users = [admin, krbtgt, orphan], PrivilegedUserDns = privileged }, Now);
        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(1, finding.Count);
    }

    [Fact]
    public void Check9_StaysNotVisibleWhenPrivilegedAccountsShowNoAdminCount()
    {
        var admin = TestObjects.User(adminCount: null) with { DistinguishedName = "CN=Administrator,CN=Users,DC=example,DC=test" };
        var directory = new FakeScanDirectory
        {
            Users = [admin],
            PrivilegedUserDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { admin.DistinguishedName },
        };
        AssertNotVisible(new OrphanedAdminCountCheck(), directory);
    }

    [Fact]
    public void Check10_PassesAt180DaysAndFailsBeyondIt()
    {
        var check = new KrbtgtPasswordAgeCheck();
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Krbtgt = TestObjects.User("krbtgt", pwdLastSet: Now.AddDays(-180)) }, Now).Status);
        Assert.Equal(CheckStatus.Fail, check.Run(new FakeScanDirectory { Krbtgt = TestObjects.User("krbtgt", pwdLastSet: Now.AddDays(-181)) }, Now).Status);
    }

    [Fact]
    public void Check10_DoesNotTurnUnreadablePwdLastSetIntoZero()
    {
        AssertNotVisible(new KrbtgtPasswordAgeCheck(), new FakeScanDirectory { Krbtgt = TestObjects.User("krbtgt", pwdLastSet: null) });
    }

    [Fact]
    public void Check11_PassesAt90DaysAndForRecentlyCreatedAccounts()
    {
        var users = new[]
        {
            TestObjects.User("edge", lastLogon: Now.AddDays(-90), created: Now.AddYears(-1)),
            TestObjects.User("new", lastLogon: Now.AddDays(-200), created: Now.AddDays(-10)),
        };
        Assert.Equal(CheckStatus.Pass, new StaleSignInCheck().Run(new FakeScanDirectory { Users = users }, Now).Status);
    }

    [Fact]
    public void Check11_FailsBeyond90Days()
    {
        var user = TestObjects.User(lastLogon: Now.AddDays(-91), created: Now.AddYears(-1));
        Assert.Equal(CheckStatus.Fail, new StaleSignInCheck().Run(new FakeScanDirectory { Users = [user] }, Now).Status);
    }

    [Fact]
    public void Check11_IsNotVisibleWhenUsersAreUnreadable()
    {
        AssertNotVisible(new StaleSignInCheck(), new FakeScanDirectory { Users = null });
    }

    [Fact]
    public void Check12_PassesAt30DaysAndFailsBeyondIt()
    {
        var check = new NeverSignedInCheck();
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Users = [TestObjects.User(created: Now.AddDays(-30))] }, Now).Status);
        Assert.Equal(CheckStatus.Fail, check.Run(new FakeScanDirectory { Users = [TestObjects.User(created: Now.AddDays(-31))] }, Now).Status);
    }

    [Fact]
    public void Check12_IsNotVisibleWhenUsersAreUnreadable()
    {
        AssertNotVisible(new NeverSignedInCheck(), new FakeScanDirectory { Users = null });
    }

    [Fact]
    public void Check13_ExcludesServiceAccountsAndFailsForOrdinaryAccounts()
    {
        var check = new NonServicePasswordNeverExpiresCheck();
        var service = TestObjects.User(uac: 0x10000, spns: ["HTTP/service"]);
        var ordinary = TestObjects.User(uac: 0x10000, spns: Array.Empty<string>());
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Users = [service] }, Now).Status);
        Assert.Equal(CheckStatus.Fail, check.Run(new FakeScanDirectory { Users = [ordinary] }, Now).Status);
    }

    [Fact]
    public void Check13_DoesNotDoubleCountPrivilegedAccountsReportedByCheck6()
    {
        var check = new NonServicePasswordNeverExpiresCheck();
        var admin = TestObjects.User("admin1", uac: 0x10000, spns: Array.Empty<string>());
        var ordinary = TestObjects.User("bob", uac: 0x10000, spns: Array.Empty<string>());
        var result = check.Run(new FakeScanDirectory { Users = [admin, ordinary], PrivilegedUserDns = new HashSet<string> { admin.DistinguishedName } }, Now);
        Assert.Equal(1, result.Count);
        Assert.DoesNotContain(admin.SamAccountName, result.Accounts);
        // Negative control: with nothing privileged both are counted.
        Assert.Equal(2, check.Run(new FakeScanDirectory { Users = [admin, ordinary], PrivilegedUserDns = new HashSet<string>() }, Now).Count);
    }

    [Fact]
    public void Check13_DoesNotTurnUnreadableSpnsIntoZero()
    {
        var user = TestObjects.User(uac: 0x10000) with { ServicePrincipalNames = null };
        AssertNotVisible(new NonServicePasswordNeverExpiresCheck(), new FakeScanDirectory { Users = [user] });
    }

    [Theory]
    [InlineData(0x20)]
    [InlineData(0x80)]
    public void Check14_FailsForEitherWeakFlag(int flag)
    {
        Assert.Equal(CheckStatus.Fail, new WeakPasswordFlagsCheck().Run(new FakeScanDirectory { Users = [TestObjects.User(uac: flag)] }, Now).Status);
    }

    [Fact]
    public void Check14_PassesWithoutFlagsAndDoesNotTurnUnreadableUacIntoZero()
    {
        var check = new WeakPasswordFlagsCheck();
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Users = [TestObjects.User(uac: 0)] }, Now).Status);
        AssertNotVisible(check, new FakeScanDirectory { Users = [TestObjects.User(uac: null)] });
    }

    [Fact]
    public void Check15_FlagsUnsupportedButNotBlankOrUnknownOperatingSystems()
    {
        var check = new UnsupportedWindowsCheck();
        Assert.Equal(CheckStatus.Fail, check.Run(new FakeScanDirectory { Computers = [TestObjects.Computer(operatingSystem: "Windows 10 Pro")] }, Now).Status);
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Computers = [TestObjects.Computer(operatingSystem: null), TestObjects.Computer("PC2$", "Samba")] }, Now).Status);
    }

    [Fact]
    public void Check15_IsNotVisibleWhenComputersAreUnreadable()
    {
        AssertNotVisible(new UnsupportedWindowsCheck(), new FakeScanDirectory { Computers = null });
    }

    [Fact]
    public void Check16_UsesHighSeverityOnlyWhenAPrivilegedAccountIsExposed()
    {
        var ordinary = TestObjects.User("svc", spns: ["HTTP/svc"]);
        var check = new KerberoastableAccountsCheck();
        var medium = check.Run(new FakeScanDirectory { Users = [ordinary] }, Now);
        Assert.Equal(CheckStatus.Fail, medium.Status);
        Assert.Equal(Severity.Medium, medium.Severity);
        var high = check.Run(WithPrivileged(ordinary), Now);
        Assert.Equal(Severity.High, high.Severity);
    }

    [Fact]
    public void Check16_PassesWithoutSpnsAndDoesNotTurnUnreadableSpnsIntoZero()
    {
        var check = new KerberoastableAccountsCheck();
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Users = [TestObjects.User()] }, Now).Status);
        var unknown = TestObjects.User() with { ServicePrincipalNames = null };
        AssertNotVisible(check, new FakeScanDirectory { Users = [unknown] });
    }

    [Fact]
    public void Check17_PassesWithoutFlagFailsWithFlagAndHandlesUnknown()
    {
        var check = new AsRepRoastableAccountsCheck();
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Users = [TestObjects.User(uac: 0)] }, Now).Status);
        Assert.Equal(CheckStatus.Fail, check.Run(new FakeScanDirectory { Users = [TestObjects.User(uac: 0x400000)] }, Now).Status);
        AssertNotVisible(check, new FakeScanDirectory { Users = [TestObjects.User(uac: null)] });
    }

    [Fact]
    public void Check18_ExcludesDomainControllersAndFindsUsersAndNonDcComputers()
    {
        var check = new UnconstrainedDelegationCheck();
        var dc = TestObjects.Computer(uac: 0x80000, primaryGroupId: 516);
        Assert.Equal(CheckStatus.Pass, check.Run(new FakeScanDirectory { Computers = [dc] }, Now).Status);
        Assert.Equal(CheckStatus.Fail, check.Run(new FakeScanDirectory { Computers = [TestObjects.Computer(uac: 0x80000)] }, Now).Status);
        Assert.Equal(CheckStatus.Fail, check.Run(new FakeScanDirectory { Users = [TestObjects.User(uac: 0x80000)] }, Now).Status);
    }

    [Fact]
    public void Check18_DoesNotTurnUnreadableDelegationDataIntoZero()
    {
        AssertNotVisible(new UnconstrainedDelegationCheck(), new FakeScanDirectory { Computers = [TestObjects.Computer(uac: null)] });
    }

    [Fact]
    public void Check19_ReportsLapsCoverageAndSeverityAtTheFiftyPercentBoundary()
    {
        var covered = TestObjects.Computer("covered$") with { HasLapsExpiry = true };
        var missing = TestObjects.Computer("missing$") with { HasLapsExpiry = false };
        var half = new LapsCoverageCheck().Run(new FakeScanDirectory { Computers = [covered, missing] }, Now);
        Assert.Equal(CheckStatus.Fail, half.Status);
        Assert.Equal(Severity.Medium, half.Severity);
        var underHalf = new LapsCoverageCheck().Run(new FakeScanDirectory { Computers = [covered, missing, TestObjects.Computer("missing2$") with { HasLapsExpiry = false }] }, Now);
        Assert.Equal(Severity.High, underHalf.Severity);
    }

    [Fact]
    public void Check19_ExcludesDisabledAndDomainControllersAndDistinguishesUnavailableLaps()
    {
        var covered = TestObjects.Computer("covered$") with { HasLapsExpiry = true };
        var disabled = TestObjects.Computer("disabled$", enabled: false) with { HasLapsExpiry = false };
        var dc = TestObjects.Computer("dc$", primaryGroupId: 516) with { HasLapsExpiry = false };
        Assert.Equal(CheckStatus.Pass, new LapsCoverageCheck().Run(new FakeScanDirectory { Computers = [covered, disabled, dc] }, Now).Status);
        var notDeployed = new LapsCoverageCheck().Run(new FakeScanDirectory { Computers = [covered], LapsSchemaPresent = false }, Now);
        Assert.Equal(CheckStatus.Fail, notDeployed.Status);
        Assert.Equal("LAPS is not deployed", notDeployed.Why);
        AssertNotVisible(new LapsCoverageCheck(), new FakeScanDirectory { LapsSchemaPresent = null });
        AssertNotVisible(new LapsCoverageCheck(), new FakeScanDirectory { Computers = [covered with { HasLapsExpiry = null }] });
    }

    [Theory]
    [InlineData(11, 10, true)]
    [InlineData(12, 0, true)]
    [InlineData(12, 11, true)]
    [InlineData(12, 10, false)]
    public void Check20_FailsEachBaselineViolation(int length, int lockout, bool complexity)
    {
        var fake = new FakeScanDirectory { PasswordPolicy = new DomainPasswordPolicy(length, lockout, complexity, TimeSpan.FromDays(90)) };
        Assert.Equal(CheckStatus.Fail, new DefaultPasswordPolicyCheck().Run(fake, Now).Status);
    }

    [Theory]
    [InlineData(12, 1, true)]
    [InlineData(12, 10, true)]
    [InlineData(14, 10, false)]
    public void Check20_PassesBaselineEdges(int length, int lockout, bool complexity)
    {
        var fake = new FakeScanDirectory { PasswordPolicy = new DomainPasswordPolicy(length, lockout, complexity, TimeSpan.FromDays(90)) };
        Assert.Equal(CheckStatus.Pass, new DefaultPasswordPolicyCheck().Run(fake, Now).Status);
    }

    [Fact]
    public void Check20_DoesNotTurnUnreadablePolicyValueIntoZero()
    {
        AssertNotVisible(new DefaultPasswordPolicyCheck(), new FakeScanDirectory { PasswordPolicy = new DomainPasswordPolicy(null, 10, true, null) });
    }

    private static FakeScanDirectory PrivilegedUsers(int count)
    {
        var users = Enumerable.Range(1, count).Select(index => TestObjects.User($"admin{index}", pwdLastSet: Now)).ToArray();
        return WithPrivileged(users);
    }

    private static FakeScanDirectory WithPrivileged(params ScanUser[] users) => new()
    {
        Users = users,
        PrivilegedUserDns = new HashSet<string>(users.Select(user => user.DistinguishedName), StringComparer.OrdinalIgnoreCase),
    };

    private static void AssertNotVisible(ICheck check, FakeScanDirectory fake)
    {
        var finding = check.Run(fake, Now);
        Assert.Equal(CheckStatus.NotVisible, finding.Status);
        Assert.Null(finding.Count);
        Assert.Null(finding.AccountsTotal);
        Assert.NotNull(finding.NotVisibleReason);
    }
}
