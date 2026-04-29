<#
.SYNOPSIS
    Applies the 'MDE-Management' device tag to a list of Microsoft Defender for
    Endpoint (MDE) devices supplied via CSV.

.DESCRIPTION
    Reads a CSV file containing MDE machine IDs and adds a fixed device tag to
    each device using the Microsoft Defender for Endpoint API.

    Authentication is performed interactively against Microsoft Entra ID using
    the MSAL.PS module (a browser window will be opened on first run).

    The signed-in user must have an Entra ID role / MDE RBAC assignment that
    grants the delegated permission 'Machine.ReadWrite.All' (or equivalent
    custom RBAC) on the target devices.

    A timestamped log file is written for every run, and a summary is printed
    at the end. The script is idempotent: re-tagging an already-tagged device
    is a no-op on the service side.

.PARAMETER CsvPath
    Path to a CSV file with a header row that includes a 'machineId' column.
    Each row must contain the MDE machineId (GUID-like SHA1 string) of one
    device. Other columns are ignored.

.PARAMETER TenantId
    Microsoft Entra ID tenant ID (GUID) or verified domain name
    (e.g. contoso.onmicrosoft.com) to authenticate against.

.PARAMETER LogDirectory
    Directory where the run log file is written. Created if it does not exist.
    Defaults to a 'Logs' subfolder next to the script.

.PARAMETER ThrottleDelayMs
    Delay between API calls in milliseconds, to stay well under MDE API rate
    limits (100 calls/min, 1500 calls/hour per tenant). Default 250 ms.

.EXAMPLE
    .\Set-MdeDeviceTag.ps1 -CsvPath .\devices.csv -TenantId contoso.onmicrosoft.com

.NOTES
    Tag value : MDE-Management   (fixed by design)
    Action    : Add               (fixed by design)
    Cloud     : Commercial        (api.securitycenter.microsoft.com)
    API ref   : https://learn.microsoft.com/defender-endpoint/api/add-or-remove-machine-tags

    Requires PowerShell 5.1+ and the MSAL.PS module:
        Install-Module MSAL.PS -Scope CurrentUser
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "CSV file not found: $_"
        }
        $true
    })]
    [string] $CsvPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    [Parameter()]
    [string] $LogDirectory = (Join-Path -Path $PSScriptRoot -ChildPath 'Logs'),

    [Parameter()]
    [ValidateRange(0, 10000)]
    [int] $ThrottleDelayMs = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Constants ---------------------------------------------------------------

# Well-known first-party client ID for "Microsoft Mobile Application Management"
# which is permitted as a public client for MDE delegated auth in samples.
# Replace with your own multi-tenant app registration's client ID if you have
# registered one (recommended for production traceability).
$script:ClientId    = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'   # Microsoft Office (public client)
$script:RedirectUri = 'http://localhost'
$script:Resource    = 'https://api.securitycenter.microsoft.com'
$script:Scopes      = @("$script:Resource/Machine.ReadWrite.All")
$script:ApiBase     = $script:Resource
$script:TagValue    = 'MDE-Management'
$script:TagAction   = 'Add'

# --- Helpers -----------------------------------------------------------------

function Initialize-Log {
    param ([string] $Directory)

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogFile = Join-Path -Path $Directory -ChildPath "Set-MdeDeviceTag_$stamp.log"
    Write-Log -Level INFO -Message "Log file: $script:LogFile"
}

function Write-Log {
    param (
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $Message
    )

    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1,-7}] {2}' -f (Get-Date), $Level, $Message

    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        default   { Write-Host $line }
    }

    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line
    }
}

function Assert-Module {
    param ([string] $Name)

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Required module '$Name' is not installed. Run: Install-Module $Name -Scope CurrentUser"
    }
    Import-Module $Name -ErrorAction Stop
}

function Get-MdeAccessToken {
    param (
        [Parameter(Mandatory)] [string] $TenantId
    )

    Write-Log -Message "Acquiring access token for tenant $TenantId (interactive)..."

    # Interactive auth via MSAL. Token cache is per-user, encrypted by MSAL.PS.
    # No secret is ever stored or logged by this script.
    $tokenResult = Get-MsalToken `
        -ClientId    $script:ClientId `
        -TenantId    $TenantId `
        -RedirectUri $script:RedirectUri `
        -Scopes      $script:Scopes `
        -Interactive

    if (-not $tokenResult -or -not $tokenResult.AccessToken) {
        throw 'Failed to acquire access token.'
    }

    Write-Log -Level SUCCESS -Message ("Token acquired for {0} (expires {1:u})." -f `
        $tokenResult.Account.Username, $tokenResult.ExpiresOn.UtcDateTime)

    return $tokenResult.AccessToken
}

function Set-MachineTag {
    <#
    .SYNOPSIS
        Calls the MDE 'Add or remove machine tags' API for a single machine.
    #>
    param (
        [Parameter(Mandatory)] [string] $MachineId,
        [Parameter(Mandatory)] [string] $AccessToken
    )

    $uri  = '{0}/api/machines/{1}/tags' -f $script:ApiBase, $MachineId
    $body = @{
        Value  = $script:TagValue
        Action = $script:TagAction
    } | ConvertTo-Json -Compress

    $headers = @{
        Authorization = "Bearer $AccessToken"
        'Content-Type' = 'application/json'
    }

    # Simple retry for transient throttling (HTTP 429) and 5xx errors.
    $maxAttempts = 4
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $null = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ErrorAction Stop
            return  # success
        }
        catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }

            $isRetryable = ($status -eq 429) -or ($status -ge 500 -and $status -lt 600)

            if ($isRetryable -and $attempt -lt $maxAttempts) {
                $wait = [Math]::Min(30, [Math]::Pow(2, $attempt))
                Write-Log -Level WARN -Message ("HTTP {0} for {1} (attempt {2}/{3}). Retrying in {4}s..." -f `
                    $status, $MachineId, $attempt, $maxAttempts, $wait)
                Start-Sleep -Seconds $wait
                continue
            }

            $msg = $_.Exception.Message
            if ($status) { $msg = "HTTP $status - $msg" }
            throw $msg
        }
    }
}

# --- Main --------------------------------------------------------------------

try {
    Initialize-Log -Directory $LogDirectory
    Write-Log -Message "Starting MDE device tagging. Tag='$script:TagValue' Action='$script:TagAction'"
    Write-Log -Message "CSV: $CsvPath"

    Assert-Module -Name 'MSAL.PS'

    $rows = Import-Csv -LiteralPath $CsvPath
    if (-not $rows) {
        Write-Log -Level WARN -Message 'CSV contains no rows. Nothing to do.'
        return
    }
    if (-not ($rows[0].PSObject.Properties.Name -contains 'machineId')) {
        throw "CSV must contain a 'machineId' column."
    }

    # De-duplicate and drop blanks up-front.
    $machineIds = $rows |
        Select-Object -ExpandProperty machineId |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique

    Write-Log -Message ("Devices to tag: {0} (after de-duplication)" -f $machineIds.Count)

    if ($machineIds.Count -eq 0) {
        Write-Log -Level WARN -Message 'No valid machineId values found. Exiting.'
        return
    }

    if (-not $PSCmdlet.ShouldProcess(
            "$($machineIds.Count) MDE device(s)",
            "Add tag '$script:TagValue'")) {
        Write-Log -Level WARN -Message 'Run cancelled (WhatIf/No confirmation).'
        return
    }

    $accessToken = Get-MdeAccessToken -TenantId $TenantId

    $success = 0
    $failed  = 0
    $failures = New-Object System.Collections.Generic.List[string]

    foreach ($id in $machineIds) {
        try {
            Set-MachineTag -MachineId $id -AccessToken $accessToken
            $success++
            Write-Log -Level SUCCESS -Message "Tagged: $id"
        }
        catch {
            $failed++
            $failures.Add($id) | Out-Null
            Write-Log -Level ERROR -Message ("Failed: {0} - {1}" -f $id, $_.Exception.Message)
        }
        finally {
            if ($ThrottleDelayMs -gt 0) { Start-Sleep -Milliseconds $ThrottleDelayMs }
        }
    }

    Write-Log -Message '----- Summary -----'
    Write-Log -Message ("Total:   {0}" -f $machineIds.Count)
    Write-Log -Level SUCCESS -Message ("Success: {0}" -f $success)
    if ($failed -gt 0) {
        Write-Log -Level ERROR -Message ("Failed:  {0}" -f $failed)
        Write-Log -Level ERROR -Message ('Failed IDs: ' + ($failures -join ', '))
        exit 1
    }
    exit 0
}
catch {
    Write-Log -Level ERROR -Message ("Fatal: {0}" -f $_.Exception.Message)
    Write-Log -Level ERROR -Message $_.ScriptStackTrace
    exit 2
}
