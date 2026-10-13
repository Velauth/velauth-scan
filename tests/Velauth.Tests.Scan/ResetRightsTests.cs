using Velauth.Scan.Checks;
using Velauth.Scan.Model;

namespace Velauth.Tests.Scan;

public sealed class ResetRightsTests
{
    private const string DomainDn = "DC=example,DC=test";
    private const string HelpdeskSid = "S-1-5-21-100-200-300-1100";

    [Fact]
    public void ResetOnOuInheritsToUsersInNestedOus()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Child,OU=Support,{DomainDn}");
        var result = Run([user], "OU=Support," + DomainDn, Ace());
        Assert.Equal(1, result.Count);
    }

    [Fact]
    public void SchemaGuidsMatchTheValuesSeenOnARealDomain()
    {
        // Observed on a real domain's ACEs (Get-Acl on an OU). A wrong user-class GUID once made the
        // scanner report 0 for a delegation that really existed, so these literals are pinned.
        Assert.Equal(new Guid("bf967aba-0de6-11d0-a285-00aa003049e2"), ResetRights.UserClassGuid);
        Assert.Equal(new Guid("00299570-246d-11d0-a768-00aa006e0529"), ResetRights.ResetPasswordGuid);
    }

    [Fact]
    public void RealLabAceShapeCounts()
    {
        // Shape copied from the lab: Allow, ExtendedRight, reset-password object type, inherited object type
        // = user class, ContainerInherit, on OU=Lab Users.
        var user = TestObjects.User(dn: $"CN=Bob,OU=Lab Users,{DomainDn}");
        var real = Ace() with { InheritedObjectType = new Guid("bf967aba-0de6-11d0-a285-00aa003049e2") };
        Assert.Equal(1, Run([user], "OU=Lab Users," + DomainDn, real).Count);
        // Negative control: the same ACE scoped to the computer class must not count for a user.
        var computer = real with { InheritedObjectType = new Guid("bf967a86-0de6-11d0-a285-00aa003049e2") };
        Assert.False(ResetRights.GrantsResetPassword(computer, onUserObject: false));
    }

    [Fact]
    public void AnotherExtendedRightDoesNotCount()
    {
        var entry = Ace() with { ObjectType = Guid.NewGuid() };
        Assert.False(ResetRights.GrantsResetPassword(entry, onUserObject: false));
    }

    [Fact]
    public void NullObjectTypeMeansAllExtendedRightsAndCounts()
    {
        Assert.True(ResetRights.GrantsResetPassword(Ace() with { ObjectType = null }, onUserObject: false));
    }

    [Fact]
    public void GenericAllCounts()
    {
        Assert.True(ResetRights.GrantsResetPassword(Ace() with
        {
            AccessMask = ResetRights.GenericAll,
            ObjectType = Guid.NewGuid(),
        }, onUserObject: false));
    }

    [Fact]
    public void FullControlCounts()
    {
        Assert.True(ResetRights.GrantsResetPassword(Ace() with
        {
            AccessMask = ResetRights.FullControl,
            ObjectType = Guid.NewGuid(),
        }, onUserObject: false));
    }

    [Fact]
    public void ComputerInheritedObjectTypeDoesNotCount()
    {
        var computerClass = new Guid("bf967a86-0de6-11d0-a285-00aa003049e2");
        Assert.False(ResetRights.GrantsResetPassword(Ace() with { InheritedObjectType = computerClass }, onUserObject: false));
    }

    [Fact]
    public void InheritOnlyAceOnContainerCountsForChildren()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Support,{DomainDn}");
        Assert.Equal(1, Run([user], "OU=Support," + DomainDn, Ace() with { InheritOnly = true }).Count);
    }

    [Fact]
    public void NoPropagateAppliesOnlyToImmediateChildren()
    {
        var direct = TestObjects.User("direct", dn: $"CN=Direct,OU=Support,{DomainDn}");
        var nested = TestObjects.User("nested", dn: $"CN=Nested,OU=Child,OU=Support,{DomainDn}");
        var finding = Run([direct, nested], "OU=Support," + DomainDn, Ace() with { NoPropagateInherit = true });
        Assert.Equal(1, finding.Count);
        Assert.Contains("direct", finding.Accounts);
        Assert.DoesNotContain("nested", finding.Accounts);
    }

    [Fact]
    public void DenyForSameTrusteeAndScopeRemovesAllow()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Support,{DomainDn}");
        var finding = Run([user], "OU=Support," + DomainDn, Ace(), Ace() with { Allow = false });
        Assert.Equal(0, finding.Count);
    }

    [Fact]
    public void DenyForAnotherTrusteeDoesNotRemoveAllow()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Support,{DomainDn}");
        var finding = Run([user], "OU=Support," + DomainDn, Ace(), Ace() with
        {
            Allow = false,
            TrusteeSid = "S-1-5-21-100-200-300-1200",
        });
        Assert.Equal(1, finding.Count);
    }

    [Fact]
    public void ProtectedChildOuStopsParentInheritance()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Protected,OU=Support,{DomainDn}");
        var fake = Fake([user], "OU=Support," + DomainDn, Ace());
        fake.ContainerAcls =
        [
            ("OU=Support," + DomainDn, new ScanAcl { Entries = [Ace()], DaclProtected = false }),
            ("OU=Protected,OU=Support," + DomainDn, new ScanAcl { Entries = [], DaclProtected = true }),
        ];
        Assert.Equal(0, new ResetDelegationCheck().Run(fake, DateTime.UnixEpoch).Count);
    }

    [Fact]
    public void AdminCountOneUserIsExcludedFromHeadline()
    {
        var user = TestObjects.User(adminCount: 1, dn: $"CN=Admin,OU=Support,{DomainDn}");
        Assert.Equal(0, Run([user], "OU=Support," + DomainDn, Ace()).Count);
    }

    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-100-200-300-512")]
    [InlineData("S-1-5-21-100-200-300-519")]
    [InlineData("S-1-3-0")]
    [InlineData("S-1-5-10")]
    [InlineData("S-1-5-9")]
    public void ExpectedTrusteesAreIgnored(string sid)
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Support,{DomainDn}");
        Assert.Equal(0, Run([user], "OU=Support," + DomainDn, Ace() with { TrusteeSid = sid }).Count);
    }

    [Fact]
    public void AuthenticatedUsersIsCritical()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Support,{DomainDn}");
        var finding = Run([user], "OU=Support," + DomainDn, Ace() with { TrusteeSid = "S-1-5-11" });
        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Equal(Severity.Critical, finding.Severity);
    }

    [Fact]
    public void DisabledUsersAreNotCountedInHeadline()
    {
        var disabled = TestObjects.User(enabled: false, dn: $"CN=Disabled,OU=Support,{DomainDn}");
        var finding = Run([disabled], "OU=Support," + DomainDn, Ace());
        var details = Assert.IsType<ResetBlastRadius>(finding.Details);
        Assert.Equal(0, finding.Count);
        Assert.Equal(0, details.EnabledUsers);
    }

    [Fact]
    public void ChecksOneTwoAndFourUseTheSameAnalysis()
    {
        var admin = TestObjects.User("operator", adminCount: 0, dn: $"CN=Operator,OU=Support,{DomainDn}");
        var fake = Fake([admin], "OU=Support," + DomainDn, Ace());
        fake.PrivilegedUserDns = new HashSet<string>([admin.DistinguishedName], StringComparer.OrdinalIgnoreCase);
        fake.NestedMemberDns[HelpdeskSid] = new HashSet<string>([admin.DistinguishedName], StringComparer.OrdinalIgnoreCase);
        fake.UserAcls[admin.DistinguishedName] = new ScanAcl { Entries = [], DaclProtected = false };
        var analysis = new BlastRadiusAnalysis();

        Assert.Equal(1, new ResetDelegationCheck(analysis).Run(fake, DateTime.UnixEpoch).Count);
        Assert.Equal(1, new ResettablePrivilegedCheck(analysis).Run(fake, DateTime.UnixEpoch).Count);
        Assert.Equal(1, new OperatorExposureCheck(analysis).Run(fake, DateTime.UnixEpoch).Count);
    }

    [Fact]
    public void UnreadableMembershipIsNotVisibleNotZero()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Support,{DomainDn}");
        var fake = Fake([user], "OU=Support," + DomainDn, Ace());
        fake.NestedMemberDns[HelpdeskSid] = null;
        var finding = new ResetDelegationCheck().Run(fake, DateTime.UnixEpoch);
        Assert.Equal(CheckStatus.NotVisible, finding.Status);
        Assert.Null(finding.Count);
    }

    [Fact]
    public void ProtectedPrivilegedUserIsNotReportedByCheckTwo()
    {
        var admin = TestObjects.User("admin", dn: $"CN=Admin,OU=Support,{DomainDn}");
        var fake = Fake([admin], "OU=Support," + DomainDn, Ace());
        fake.PrivilegedUserDns = new HashSet<string>([admin.DistinguishedName], StringComparer.OrdinalIgnoreCase);
        fake.UserAcls[admin.DistinguishedName] = new ScanAcl { Entries = [], DaclProtected = true };
        Assert.Equal(CheckStatus.Pass, new ResettablePrivilegedCheck().Run(fake, DateTime.UnixEpoch).Status);
    }

    [Fact]
    public void AdminSdHolderFlagsPowerfulNonDefaultAllow()
    {
        var fake = new FakeScanDirectory
        {
            AdminSdHolderAcl = new ScanAcl
            {
                Entries = [Ace() with { AccessMask = ResetRights.WriteDacl, ContainerInherit = false }],
                DaclProtected = true,
            },
        };
        fake.TrusteeNames[HelpdeskSid] = "Helpdesk";
        var finding = new AdminSdHolderCheck().Run(fake, DateTime.UnixEpoch);
        Assert.Equal(CheckStatus.Fail, finding.Status);
        Assert.Contains("WriteDacl", Assert.Single(finding.Accounts));
    }

    [Fact]
    public void ManagedServiceAccountTrusteeIsLabelledAsServiceAccount()
    {
        var user = TestObjects.User(dn: $"CN=Alice,OU=Support,{DomainDn}");
        var fake = Fake([user], "OU=Support," + DomainDn, Ace());
        fake.TrusteeKinds[HelpdeskSid] = "Service account";
        var finding = new ResetDelegationCheck().Run(fake, DateTime.UnixEpoch);
        var details = Assert.IsType<ResetBlastRadius>(finding.Details);
        Assert.Equal("Service account", Assert.Single(details.TopPrincipals).Kind);
    }

    private static Finding Run(IReadOnlyList<ScanUser> users, string containerDn, params AclEntry[] entries) =>
        new ResetDelegationCheck().Run(Fake(users, containerDn, entries), DateTime.UnixEpoch);

    private static FakeScanDirectory Fake(IReadOnlyList<ScanUser> users, string containerDn, params AclEntry[] entries)
    {
        var fake = new FakeScanDirectory
        {
            Users = users,
            ContainerAcls = [(containerDn, new ScanAcl { Entries = entries, DaclProtected = false })],
        };
        fake.TrusteeNames[HelpdeskSid] = "Helpdesk";
        fake.NestedMemberDns[HelpdeskSid] = new HashSet<string>(["CN=Tech," + DomainDn], StringComparer.OrdinalIgnoreCase);
        fake.GroupSids.Add(HelpdeskSid);
        return fake;
    }

    private static AclEntry Ace() => new()
    {
        TrusteeSid = HelpdeskSid,
        Allow = true,
        AccessMask = ResetRights.ExtendedRight,
        ObjectType = ResetRights.ResetPasswordGuid,
        InheritedObjectType = ResetRights.UserClassGuid,
        ContainerInherit = true,
        InheritOnly = false,
        NoPropagateInherit = false,
        IsInherited = false,
    };
}
