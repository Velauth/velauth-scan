# velauth-scan

A free, open-source, read-only Active Directory exposure scanner from [Velauth](https://velauth.com). It runs 20 checks against your own domain, mostly about what a helpdesk or delegated operator could do to privileged accounts, and writes one self-contained HTML report plus one JSON evidence file.

## Authorised use only

Run this only against Active Directory environments you own or have written permission to assess. It reads directory data (users, groups, permissions on directory objects). Treat the reports as sensitive: they describe weaknesses in a live directory.

## What it does and does not do

- Read-only LDAP searches as the current Windows identity. It never changes Active Directory.
- No telemetry, no update check, no cloud calls, no credential prompt. The only network traffic is LDAP to the domain controller.
- `--list-queries` prints every LDAP filter it uses, without contacting a directory.
- A finding is evidence for review. It is not a certification and not a statement of compliance. Where the scan cannot read something, it says "Not visible to this scan" and never reports zero.
- Provided as is, without warranty (Apache License 2.0).

## Build and test

Requires the .NET 8 SDK.

```
dotnet build src/Velauth.Scan -c Release
dotnet test tests/Velauth.Tests.Scan
dotnet publish src/Velauth.Scan -c Release -r win-x64 --self-contained
```

Full usage, check list and the "helpdesk blast radius" method are in [src/Velauth.Scan/README.md](src/Velauth.Scan/README.md).

## Releases

Each release lists the SHA-256 of `velauth-scan.exe`. Compare it with `Get-FileHash .\velauth-scan.exe -Algorithm SHA256` before running. Releases are not yet code signed.

## License

Apache License 2.0. See [LICENSE](LICENSE).
