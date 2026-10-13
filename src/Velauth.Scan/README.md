# Velauth AD Helpdesk Exposure Scan

`velauth-scan` is a small, open-source Windows console scanner. It binds to Active Directory as the current Windows identity, performs read-only LDAP searches, and writes one self-contained HTML report plus one JSON evidence file. MSPs and consultants may use it on client networks with permission.

It never changes Active Directory. It has no telemetry, update check, cloud API, Microsoft Graph dependency, web request, or credential prompt. The only network traffic it creates is LDAP to the selected or discovered domain controller. A result is evidence for review, not a certification or statement of compliance.

## Run

```powershell
.\velauth-scan.exe --out C:\Reports
.\velauth-scan.exe --dc dc01.example.com --domain example.com --company "Example MSP" --logo .\logo.png
.\velauth-scan.exe --list-queries
```

Options:

```text
velauth-scan [--out DIR] [--dc HOST] [--domain FQDN] [--company TEXT] [--logo FILE] [--list-queries] [--version]
```

The logo must be PNG or SVG and no larger than 200 KB. It is embedded in the report as a data URI. `--list-queries` prints every LDAP filter template without contacting a directory.

## Verify the executable

Verify the Authenticode signer and the downloaded file hash before running a release:

```powershell
Get-AuthenticodeSignature .\velauth-scan.exe | Format-List Status,StatusMessage,SignerCertificate
Get-FileHash .\velauth-scan.exe -Algorithm SHA256
```

Compare the SHA-256 value with the value published alongside that release. A source build is not signed automatically. The JSON field `reportSha256` is different: it is the SHA-256 of canonical JSON for the findings, with stable property order, UTF-8, and no whitespace. It lets reviewers detect a changed finding set, but it is not a digital signature.

## Helpdesk blast radius

The page-one number counts enabled users whose inherited container permissions let at least one non-default trustee reset their password. The scanner reads DACLs on the domain root, every OU, and the built-in Users and Computers containers. An allow ACE counts when it applies to user objects and grants one of these rights:

- Reset Password (`00299570-246d-11d0-a768-00aa006e0529`) through the ExtendedRight mask (`0x00000100`), including a blank object type for all extended rights.
- GenericAll (`0x10000000`) or the Active Directory full-control mask (`0x000F01FF`).

The user class schema GUID is `bf967aba-0de6-11d0-a285-00aa003049e2`. Container inheritance, inherit-only ACEs, and no-propagate inheritance are honored. A no-propagate ACE reaches immediate children only. A deny ACE removes the same reset capability for the same trustee and user scope; this is intentionally a focused simplification and is not a general-purpose Windows access-check engine. A deny for another trustee does not cancel an allow.

SYSTEM, Administrators, Domain Admins, Enterprise Admins, CREATOR OWNER, SELF, and Enterprise Domain Controllers are expected owners and are excluded from helpdesk delegation. Account Operators remains visible. Everyone, Authenticated Users, and Domain Users reset delegation is Critical.

For ordinary users the scanner does not read every object DACL. It assumes container inheritance is enabled unless `adminCount=1`; those users are excluded from the headline and assessed by the privileged checks. Privileged users receive individual DACL reads, capped at 500. Unreadable ACLs or nested membership make the dependent result `Not visible to this scan`, never zero.

The number does not include every possible takeover path. In particular, it does not expand delegation through other ACL capabilities such as writing `userAccountControl`, changing group membership, resource-based constrained delegation, or changing an object's DACL or owner outside the rules described above. Complex deny interactions beyond the same-trustee simplification also require manual review.

This version runs 20 checks.

## Checks

1. Password reset delegation blast radius
2. Privileged accounts exposed to delegated reset
3. AdminSDHolder powerful permissions
4. Delegated operators exposed to reset
5. Privileged group members
6. Privileged password exposure
7. Privileged accounts without delegation protection
8. Privileged accounts that look like daily-use accounts
9. Orphaned adminCount accounts
10. krbtgt password age
11. Enabled accounts inactive for 90 days
12. Enabled accounts that never signed in
13. Password never expires on non-service accounts
14. Weak password account flags
15. Computers on unsupported Windows versions
16. Kerberoastable user accounts
17. AS-REP roastable accounts
18. Unconstrained delegation
19. LAPS coverage
20. Default domain password policy

## Scoring

Only failed checks add points: Critical 25, High 10, Medium 4, Low 1, Info 0. The sum maps to A=0-4, B=5-14, C=15-29, D=30-49, and F=50 or more; there is no E. Any Critical failure caps the grade at D, and any High failure caps it at C. A finding that is Not visible adds no points and never counts as a pass. If fewer than 70 percent of the 20 checks can run, the grade is `Incomplete` instead of a letter.

## LDAP searches and attributes

The executable prints this filter list with `--list-queries`. At runtime, the HTML and JSON include the actual base DN and filter for every search that ran, in order.

```text
Base: <domain DN> | Filter: (objectClass=domainDNS)
Base: <domain DN> | Filter: (&(objectCategory=computer)(primaryGroupID=516))
Base: <configuration DN> | Filter: (&(objectClass=crossRef)(nCName=<domain DN>))
Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user))
Base: <domain DN> | Filter: (objectCategory=computer)
Base: <schema DN> | Filter: (&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)))
Base: <domain DN> | Filter: (objectSid=<well-known SID bytes>)
Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=<group DN>))
Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user)(sAMAccountName=krbtgt))
Base: <domain DN> | Filter: (|(objectClass=domainDNS)(objectClass=organizationalUnit)(distinguishedName=CN=Users,<domain DN>)(distinguishedName=CN=Computers,<domain DN>)) | SecurityMasks: Dacl
Base: CN=AdminSDHolder,CN=System,<domain DN> | Filter: (objectClass=container) | SecurityMasks: Dacl
Base: <user DN> | Filter: (objectClass=user) | SecurityMasks: Dacl
Base: <domain DN> | Filter: (objectSid=<trustee SID bytes>)
Base: <domain DN> | Filter: (&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=<trustee group DN>))
```

It reads these RootDSE values: `defaultNamingContext`, `configurationNamingContext`, `schemaNamingContext`.

It requests these domain and cross-reference attributes: `objectSid`, `msDS-Behavior-Version`, `nETBIOSName`, `minPwdLength`, `lockoutThreshold`, `pwdProperties`, `maxPwdAge`, `distinguishedName`, and `nTSecurityDescriptor` with `SecurityMasks.Dacl` for ACL reads.

It requests these user attributes: `sAMAccountName`, `distinguishedName`, `userAccountControl`, `lastLogonTimestamp`, `whenCreated`, `pwdLastSet`, `adminCount`, `servicePrincipalName`, `mail`, `msExchMailboxGuid`.

It requests these computer attributes: `sAMAccountName`, `distinguishedName`, `userAccountControl`, `operatingSystem`, `primaryGroupID`, `msLAPS-PasswordExpirationTime`, and `ms-Mcs-AdmPwdExpirationTime`. It never reads `msLAPS-Password`, `msLAPS-EncryptedPassword`, or `ms-Mcs-AdmPwd`.

Trustee resolution requests `objectSid`, `distinguishedName`, `sAMAccountName`, and `objectClass`. Nested delegated-group membership requests `distinguishedName` with the same matching-rule-in-chain behavior used for privileged groups.

Privileged and Protected Users groups are resolved by domain SID plus well-known RID, never by localized group name. Nested user membership uses LDAP matching rule in chain `1.2.840.113556.1.4.1941`. The privileged RIDs in this slice are 512, 519, 518, 544, 548, 551, 549, and 550. Protected Users is RID 525.

If you run this on a network where Velauth's own service account holds reset rights, it will appear as a delegate. That is correct.

`lastLogonTimestamp` is replicated with normal lag, so inactivity dates are approximate. A blank or unrecognized operating system is left unknown and is never labeled supported or unsupported. Attributes or queries the current user cannot read become Not visible where the check depends on them, never a zero or a pass.

## Build and test

```powershell
dotnet build Velauth.sln -c Release
dotnet test tests/Velauth.Tests.Scan/Velauth.Tests.Scan.csproj
dotnet publish src/Velauth.Scan/Velauth.Scan.csproj -c Release -r win-x64 --self-contained -o .\publish
```

Licensed under Apache-2.0. See `LICENSE`.
