using Velauth.Scan.Checks;

namespace Velauth.Tests.Scan;

public sealed class OsSupportClassifierTests
{
    private static readonly DateTime Now = new(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData("Windows Server 2003", "Windows Server 2003")]
    [InlineData("Windows Server 2008 R2 Standard", "Windows Server 2008 R2")]
    [InlineData("Windows Server 2008 Enterprise", "Windows Server 2008")]
    [InlineData("Windows Server 2012 R2 Datacenter", "Windows Server 2012 R2")]
    [InlineData("Windows Server 2012 Standard", "Windows Server 2012")]
    [InlineData("Windows XP Professional", "Windows XP")]
    [InlineData("Windows 7 Professional", "Windows 7")]
    [InlineData("Windows 8.1 Pro", "Windows 8.1")]
    [InlineData("Windows 8 Enterprise", "Windows 8")]
    [InlineData("Windows 10 Pro", "Windows 10")]
    [InlineData("Windows 10 Enterprise", "Windows 10")]
    public void IsUnsupportedAsOfOctober2026(string operatingSystem, string product)
    {
        var result = OsSupportClassifier.Classify(operatingSystem, Now);
        Assert.Equal(OsSupportStatus.Unsupported, result.Status);
        Assert.Equal(product, result.Product);
        Assert.NotNull(result.EndOfSupport);
    }

    [Fact]
    public void Server2016IsEndingSoon()
    {
        var result = OsSupportClassifier.Classify("Windows Server 2016 Standard", Now);
        Assert.Equal(OsSupportStatus.EndingSoon, result.Status);
        Assert.Equal(new DateOnly(2027, 1, 12), result.EndOfSupport);
    }

    [Theory]
    [InlineData("Windows 11 Pro")]
    [InlineData("Windows Server 2019 Standard")]
    [InlineData("Windows Server 2022 Standard Evaluation")]
    [InlineData("Windows Server 2025 Standard Evaluation")]
    public void SupportedOperatingSystemsAreSupported(string operatingSystem)
    {
        Assert.Equal(OsSupportStatus.Supported, OsSupportClassifier.Classify(operatingSystem, Now).Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Samba")]
    [InlineData("Mac OS X")]
    [InlineData("Ubuntu 22.04")]
    [InlineData("Windows Embedded 99")]
    public void UnknownValuesAreNeverFlagged(string? operatingSystem)
    {
        Assert.Equal(new OsSupport(OsSupportStatus.Unknown, string.Empty, null), OsSupportClassifier.Classify(operatingSystem, Now));
    }

    [Fact]
    public void PrefersTheSpecificProduct()
    {
        Assert.Equal(new DateOnly(2023, 1, 10), OsSupportClassifier.Classify("Windows 8.1 Pro", Now).EndOfSupport);
        Assert.Equal(new DateOnly(2016, 1, 12), OsSupportClassifier.Classify("Windows 8 Pro", Now).EndOfSupport);
        Assert.Equal("Windows Server 2012 R2", OsSupportClassifier.Classify("Windows Server 2012 R2 Standard", Now).Product);
    }

    [Fact]
    public void MovesThroughLifecycleWithClock()
    {
        const string operatingSystem = "Windows Server 2019 Standard";
        Assert.Equal(OsSupportStatus.Supported, OsSupportClassifier.Classify(operatingSystem, new DateTime(2026, 10, 9, 0, 0, 0, DateTimeKind.Utc)).Status);
        Assert.Equal(OsSupportStatus.EndingSoon, OsSupportClassifier.Classify(operatingSystem, new DateTime(2028, 6, 1, 0, 0, 0, DateTimeKind.Utc)).Status);
        Assert.Equal(OsSupportStatus.Unsupported, OsSupportClassifier.Classify(operatingSystem, new DateTime(2029, 2, 1, 0, 0, 0, DateTimeKind.Utc)).Status);
    }

    [Fact]
    public void MatchingIsCaseInsensitive()
    {
        Assert.Equal(OsSupportStatus.Unsupported, OsSupportClassifier.Classify("WINDOWS SERVER 2008 R2 STANDARD", Now).Status);
    }

    [Fact]
    public void NoteIncludesEsuOnlyForWindows10()
    {
        Assert.Contains("Extended Security Updates", OsSupportClassifier.Note(OsSupportClassifier.Classify("Windows 10 Pro", Now)));
        Assert.DoesNotContain("Extended Security Updates", OsSupportClassifier.Note(OsSupportClassifier.Classify("Windows 7 Professional", Now)));
        Assert.Contains("2020-01-14", OsSupportClassifier.Note(OsSupportClassifier.Classify("Windows 7 Professional", Now)));
        Assert.Equal(string.Empty, OsSupportClassifier.Note(OsSupportClassifier.Classify("Windows 11 Pro", Now)));
    }
}
