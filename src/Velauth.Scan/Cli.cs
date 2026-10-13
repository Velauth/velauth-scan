using Velauth.Scan.Directory;
using Velauth.Scan.Report;

namespace Velauth.Scan;

public static class Cli
{
    public static int Run(string[] args)
    {
        var parsed = Parse(args);
        if (parsed.Error is not null)
        {
            Console.Error.WriteLine(parsed.Error);
            PrintUsage(Console.Error);
            return 64;
        }
        if (parsed.Help)
        {
            PrintUsage(Console.Out);
            return 0;
        }
        if (parsed.Version)
        {
            Console.WriteLine(typeof(Cli).Assembly.GetName().Version?.ToString() ?? "0.0.0");
            return 0;
        }
        if (parsed.ListQueries)
        {
            foreach (var query in LdapScanDirectory.QueryCatalog)
                Console.WriteLine(query);
            return 0;
        }

        try
        {
            var outputDirectory = Path.GetFullPath(parsed.OutputDirectory ?? Environment.CurrentDirectory);
            System.IO.Directory.CreateDirectory(outputDirectory);
            var directory = new LdapScanDirectory(parsed.DomainController, parsed.Domain);
            var result = ScanRunner.Run(directory, DateTime.UtcNow);
            var stamp = result.GeneratedUtc.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
            var jsonPath = Path.Combine(outputDirectory, $"velauth-scan-{stamp}.json");
            var htmlPath = Path.Combine(outputDirectory, $"velauth-scan-{stamp}.html");
            ReportWriter.WriteJson(jsonPath, result);
            ReportWriter.WriteHtml(htmlPath, result, parsed.Company, parsed.LogoPath);
            Console.WriteLine($"Grade: {result.Grade}");
            Console.WriteLine($"Findings: {result.Findings.Count(finding => finding.Status == Model.CheckStatus.Fail)} failed, {result.Findings.Count(finding => finding.Status == Model.CheckStatus.Pass)} passed, {result.Findings.Count(finding => finding.Status == Model.CheckStatus.NotVisible)} not visible");
            Console.WriteLine($"HTML: {htmlPath}");
            Console.WriteLine($"JSON: {jsonPath}");
            return 0;
        }
        catch (DirectoryUnavailableException exception)
        {
            Console.Error.WriteLine($"Directory unavailable: {exception.Message}");
            return 2;
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine($"Invalid argument: {exception.Message}");
            return 64;
        }
        catch (IOException exception)
        {
            Console.Error.WriteLine($"Could not write the report: {exception.Message}");
            return 1;
        }
        catch (UnauthorizedAccessException exception)
        {
            Console.Error.WriteLine($"Could not write the report: {exception.Message}");
            return 1;
        }
    }

    private static Options Parse(IReadOnlyList<string> args)
    {
        var options = new Options();
        for (var index = 0; index < args.Count; index++)
        {
            var argument = args[index];
            switch (argument)
            {
                case "-h" or "--help": options.Help = true; break;
                case "--version": options.Version = true; break;
                case "--list-queries": options.ListQueries = true; break;
                case "--out": options.OutputDirectory = NextValue(args, ref index, argument, options); break;
                case "--dc": options.DomainController = NextValue(args, ref index, argument, options); break;
                case "--domain": options.Domain = NextValue(args, ref index, argument, options); break;
                case "--company": options.Company = NextValue(args, ref index, argument, options); break;
                case "--logo": options.LogoPath = NextValue(args, ref index, argument, options); break;
                default: options.Error = $"Unknown argument: {argument}"; return options;
            }
            if (options.Error is not null)
                return options;
        }
        return options;
    }

    private static string? NextValue(IReadOnlyList<string> args, ref int index, string argument, Options options)
    {
        if (index + 1 >= args.Count || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            options.Error = $"{argument} requires a value.";
            return null;
        }
        return args[++index];
    }

    private static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine("Usage: velauth-scan [--out DIR] [--dc HOST] [--domain FQDN] [--company TEXT] [--logo FILE] [--list-queries] [--version]");
        writer.WriteLine("Reads Active Directory over LDAP and writes a self-contained HTML report plus JSON evidence.");
    }

    private sealed class Options
    {
        public string? OutputDirectory { get; set; }
        public string? DomainController { get; set; }
        public string? Domain { get; set; }
        public string? Company { get; set; }
        public string? LogoPath { get; set; }
        public bool ListQueries { get; set; }
        public bool Version { get; set; }
        public bool Help { get; set; }
        public string? Error { get; set; }
    }
}
