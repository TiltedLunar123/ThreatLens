# Sigma Starter Pack

This directory ships a small, curated set of Sigma rules so that the
`--sigma-rules` flag works out of the box without needing to clone the
full SigmaHQ repository.

## What is included

Each rule is hand-written for ThreatLens and uses only the subset of Sigma
syntax that the loader supports today (see the **Sigma Rules** section in
the project README). All rules are tagged with MITRE ATT&CK techniques
and a severity level.

The pack mirrors the built-in detection coverage and intentionally stays
small. For broader Sigma coverage, point `--sigma-rules` at a checkout of
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

| File | Catches | MITRE |
| --- | --- | --- |
| `windows/credential_access_lsass_dump.yml` | LSASS memory access via Sysmon Event ID 10 with suspicious access masks | T1003.001 |
| `windows/credential_access_sam_hive.yml` | Direct SAM registry hive access through reg.exe save | T1003.002 |
| `windows/credential_access_dcsync.yml` | DCSync via 4662 replication GUIDs from a non-DC account | T1003.006 |
| `windows/credential_access_mimikatz_cli.yml` | Mimikatz command-line invocations and known aliases | T1003 |
| `windows/discovery_recon_burst.yml` | Rapid bursts of whoami / net / nltest / systeminfo by one user | T1082, T1087 |
| `windows/execution_encoded_powershell.yml` | PowerShell launched with -EncodedCommand or -e | T1059.001 |
| `windows/execution_certutil_download.yml` | certutil.exe used as a download cradle | T1105 |
| `windows/execution_mshta_remote.yml` | mshta.exe loading remote HTA payloads | T1218.005 |
| `windows/execution_rundll32_no_args.yml` | rundll32.exe invoked without arguments (Cobalt-Strike fingerprint) | T1218.011 |
| `windows/initial_access_external_rdp.yml` | 4624 LogonType 10 from a non-RFC1918 source | T1078 |
| `windows/lateral_movement_psexec.yml` | PSEXESVC service creation followed by remote logon | T1021.002 |
| `windows/persistence_run_key.yml` | New HKCU/HKLM Run key value pointing into AppData or Temp | T1547.001 |
| `windows/persistence_scheduled_task.yml` | Scheduled task creation pointing into Temp or with PowerShell payload | T1053.005 |
| `windows/persistence_new_service.yml` | New service (7045) with ImagePath in Temp or Downloads | T1543.003 |
| `windows/defense_evasion_log_clear.yml` | Security log cleared via 1102 | T1070.001 |
| `windows/defense_evasion_disable_defender.yml` | Windows Defender real-time protection disabled via 5001 | T1562.001 |
| `windows/privilege_escalation_sedebug.yml` | SeDebugPrivilege / SeTcbPrivilege granted to a non-system account | T1134 |
| `windows/kerberos_tgs_rc4.yml` | TGS request with RC4 encryption type for a non-machine account | T1558.003 |
| `linux/credential_access_sudo_etc_shadow.yml` | sudo reads /etc/shadow | T1003.008 |
| `linux/initial_access_ssh_brute.yml` | Repeated invalid-user SSH attempts from one source | T1110.001 |

## Usage

```bash
threatlens scan logs/ --sigma-rules rules/sigma_starter/
```

`--sigma-rules` accepts a single file, a directory, or a directory of
sub-directories. The loader walks recursively.

## Authorship and License

The rules in this folder were written by the ThreatLens author and are
covered by the same MIT License as the rest of the project. They are not
imported from SigmaHQ; the SigmaHQ project remains the authoritative
source for community Sigma content. If you contribute a new rule here,
make sure it is original or carries a compatible license.
