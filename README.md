# MDE Device Tag Script

A PowerShell script for bulk-applying the `MDE-Management` device tag to Microsoft Defender for Endpoint (MDE) devices using the MDE API.

Designed for production use: interactive auth (no secrets), input validation, retry on throttling, timestamped logging, `-WhatIf` support, and clear exit codes.

---

## Contents

| File | Purpose |
| --- | --- |
| `Set-MdeDeviceTag.ps1` | The script |
| `devices.sample.csv` | Example CSV input format |
| `Logs/` | Created on first run; one log file per run |

---

## Prerequisites

### Runtime

- **Windows PowerShell 5.1** or **PowerShell 7+**
- Internet access to:
  - `login.microsoftonline.com` (Microsoft Entra ID)
  - `api.securitycenter.microsoft.com` (MDE API – Commercial cloud)
- Execution policy allowing local scripts:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```

### PowerShell module

The script depends on the **MSAL.PS** module for interactive Entra ID authentication:

```powershell
Install-Module MSAL.PS -Scope CurrentUser
```

If your machine is offline, download the module on a connected machine with `Save-Module MSAL.PS -Path .\` and copy the folder to a `$env:PSModulePath` location on the target machine.

### Permissions

The signed-in user must have an Entra ID role / MDE RBAC assignment that grants the delegated permission **`Machine.ReadWrite.All`** (or an equivalent custom MDE RBAC role with "Manage security settings" / "Tag management") on the target devices.

Typical roles that satisfy this:
- Microsoft Defender for Endpoint **Security Administrator** (custom RBAC)
- Entra ID **Security Administrator** (when MDE RBAC is not enforced)

> The script uses a Microsoft first-party public client ID for sign-in, so **no app registration is strictly required to run it**. For production traceability and least-privilege control we recommend registering your own multi-tenant public client app and replacing the `$script:ClientId` value in the script with its Application (client) ID. The app needs:
> - Platform: **Mobile and desktop** with redirect URI `http://localhost`
> - Delegated permission: `WindowsDefenderATP / Machine.ReadWrite.All` (admin consent granted)

### MDE environment

The script targets the **Commercial** cloud (`api.securitycenter.microsoft.com`). For GCC / GCC High / DoD, change `$script:Resource` and `$script:ApiBase` near the top of the script to the appropriate endpoint:

| Cloud | Endpoint |
| --- | --- |
| Commercial | `https://api.securitycenter.microsoft.com` |
| GCC | `https://api-gcc.securitycenter.microsoft.us` |
| GCC High / DoD | `https://api-gov.securitycenter.microsoft.us` |

---

## Input CSV format

A header row with at least a `machineId` column. Other columns are ignored. Blank rows and duplicates are removed automatically.

```csv
machineId
0a1b2c3d4e5f6789...sha1...
1234567890abcdef...sha1...
```

The `machineId` is the SHA1-style identifier MDE uses internally (visible in the Defender portal device URL, or via `GET /api/machines`).

---

## Usage

### Basic

```powershell
.\Set-MdeDeviceTag.ps1 `
    -CsvPath  .\devices.csv `
    -TenantId contoso.onmicrosoft.com
```

A browser window opens for sign-in on first run. The token is cached by MSAL.PS for the duration of the session.

### Dry run (no API calls)

```powershell
.\Set-MdeDeviceTag.ps1 -CsvPath .\devices.csv -TenantId <tenant> -WhatIf
```

### Custom log location and throttle

```powershell
.\Set-MdeDeviceTag.ps1 `
    -CsvPath        .\devices.csv `
    -TenantId       <tenant-guid> `
    -LogDirectory   D:\Logs\MDE `
    -ThrottleDelayMs 500
```

### Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `-CsvPath` | Yes | – | Path to CSV with `machineId` column |
| `-TenantId` | Yes | – | Entra ID tenant GUID or domain name |
| `-LogDirectory` | No | `.\Logs` next to the script | Directory for the run log |
| `-ThrottleDelayMs` | No | `250` | Delay between API calls (ms). Stay ≤ MDE limits (100/min, 1500/hr) |
| `-WhatIf` / `-Confirm` | No | – | Standard PowerShell safety switches |

---

## Behaviour

- **Tag value**: `MDE-Management` (hard-coded)
- **Action**: `Add` (hard-coded; the API is idempotent – re-tagging is a no-op)
- **Retry**: On HTTP `429` or `5xx`, retries up to 4 times with exponential back-off (2s → 4s → 8s, capped at 30s)
- **Logging**: One log file per run at `<LogDirectory>\Set-MdeDeviceTag_<yyyyMMdd-HHmmss>.log`, plus colorised console output
- **Summary**: Total / Success / Failed counts and list of failed `machineId`s

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All devices tagged successfully |
| `1` | One or more devices failed (partial success) |
| `2` | Fatal error (bad input, auth failure, missing module, etc.) |

Suitable for use in scheduled tasks or CI pipelines that branch on exit code.

---

## Security notes

- **No secrets in code or config.** Authentication is interactive; tokens live only in memory and the per-user MSAL.PS encrypted cache.
- **No PII or token material is logged.** Only the signed-in UPN, token expiry, and per-device machineId / status are written.
- **Idempotent and reversible.** The MDE tag API supports a matching `Remove` action if a rollback is required (not exposed by this script by design).
- **Least privilege.** Operators only need delegated `Machine.ReadWrite.All`; no app secret, certificate, or Graph permissions.

---

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `Required module 'MSAL.PS' is not installed` | `Install-Module MSAL.PS -Scope CurrentUser` |
| `AADSTS65001` consent error | Tenant admin must grant consent for `Machine.ReadWrite.All` on the client app being used |
| `HTTP 403 Forbidden` | Signed-in user lacks MDE RBAC permission on the target device |
| `HTTP 404` for a machineId | Wrong ID, device decommissioned, or device is in a different tenant |
| Repeated `HTTP 429` | Increase `-ThrottleDelayMs` (e.g. `1000`); the script already retries with back-off |
| Browser does not open | Run from an interactive desktop session; for headless hosts switch to device-code or app-only auth (not included in this script) |

---

## License / Support

Provided as-is. Review and test in a non-production tenant before production rollout.
