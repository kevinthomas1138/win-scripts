# Windows 10/11 De-bloat Script (Annotated)
# This annotated version explains what each section changes and the trade-offs.
# Run with -WhatIf to simulate, -Verbose for more detail, and consider a restore point.

[CmdletBinding(SupportsShouldProcess = $true)]
# --- PARAMETERS ---------------------------------------------------------------
# These switches let you skip certain categories. Run with -WhatIf to dry-run.

param(
    [switch]$SkipAppxPackages,
    [switch]$SkipOptionalFeatures,
    [switch]$SkipScheduledTasks,
    [switch]$SkipOneDriveRemoval
)

<#
.SYNOPSIS
Removes common Windows 10/11 bloatware and disables related features with safe guards.

.DESCRIPTION
`de-bloat.ps1` is a defensive Windows clean-up script that focuses on minimizing
errors by validating the existence of every resource (AppX package, optional feature,
scheduled task, and OneDrive installation) before attempting to modify it.  Each
operation is wrapped in an error handler so the script can continue execution even if a
particular action fails.  The script supports `-WhatIf` / `-Confirm` for dry-runs.

.PARAMETER SkipAppxPackages
Skips removal of bundled AppX applications.

.PARAMETER SkipOptionalFeatures
Skips disabling optional Windows features.

.PARAMETER SkipScheduledTasks
Skips disabling scheduled tasks related to data collection / gaming services.

.PARAMETER SkipOneDriveRemoval
Skips the OneDrive removal routine.
#>

$ErrorActionPreference = 'Stop'

# ======================================================
# Wraith Logging System (Dynamic Path w/ Logs Folder)
# ======================================================
# This logger automatically writes to a "Logs" folder
# inside the directory where the script resides.
# If run interactively (pasted in console), it writes to
# "<current directory>\Logs".
# ======================================================

# Determine the base folder where script is located or run from
if ($MyInvocation.MyCommand.Path) {
    # Script executed as a file
    $BaseFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    # Script pasted into console or run inline
    $BaseFolder = (Get-Location).Path
}

# Ensure a "Logs" subfolder exists
$LogRoot = Join-Path $BaseFolder "Logs"
if (!(Test-Path -Path $LogRoot)) {
    New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
}

# Generate timestamped log file name
$LogPath = Join-Path $LogRoot ("wraith-log_{0:yyyy-MM-dd_HH-mm-ss}.txt" -f (Get-Date))

# Define Write-Log helper
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "$stamp [$Level] $Message"
    $entry | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Output $entry
}

Write-Log "Logger initialized at $LogPath"

# Checks whether the current PowerShell session is running with Administrator rights.
# --- FUNCTION: Test-IsAdministrator -------------------------------------------
# Purpose: Checks whether the current PowerShell session has admin rights.
# Impact: No changes; used to warn/guard operations needing elevation.

function Test-IsAdministrator {
    [CmdletBinding()]
    param()

    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Log -Level 'WARN' -Message "Unable to determine administrator status: $($_.Exception.Message)"
        return $false
    }
}

# Executes a script block with error handling while describing the operation.
# --- FUNCTION: Invoke-Safely ---------------------------------------------------
# Purpose: Wrapper that runs an action with try/catch and logs success/failure.
# Impact: No changes by itself; centralizes error handling and messaging.

function Invoke-Safely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    try {
        & $Action
        Write-Log -Message "$Description completed successfully."
    } catch {
        Write-Log -Level 'WARN' -Message "$Description failed: $($_.Exception.Message)"
    }
}

# Removes an AppX package for all users after verifying it exists.
# --- FUNCTION: Remove-AppxPackageSafe -----------------------------------------
# Purpose: Uninstalls a bundled Microsoft Store app (AppX) for the current user
#          only if it exists; logs and skips if not found.
# Impact: Removes selected consumer/built-in apps to reduce clutter/telemetry.
# Risks: Users of these apps lose them; they can be reinstalled from the Store.

function Remove-AppxPackageSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$PackageName
    )

    $installedPackages = Get-AppxPackage -Name $PackageName -AllUsers -ErrorAction SilentlyContinue
    if (-not $installedPackages) {
        Write-Log -Message "AppX package '$PackageName' is not installed. Skipping."
        return
    }

    foreach ($package in $installedPackages) {
        if ($PSCmdlet.ShouldProcess($package.PackageFullName, 'Remove-AppxPackage')) {
            Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
        }
    }

    $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $PackageName }
    foreach ($prov in $provisionedPackages) {
        if ($PSCmdlet.ShouldProcess($prov.PackageName, 'Remove-AppxProvisionedPackage')) {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
        }
    }
}

# Disables an optional Windows feature only if it is present and enabled.
# --- FUNCTION: Disable-OptionalFeatureSafe ------------------------------------
# Purpose: Disables a Windows Optional Feature *only* if present and enabled.
# Impact: Turns off legacy or rarely used features (e.g., Fax, XPS, PS v2).
# Risks: Software depending on these features may need them re-enabled.

function Disable-OptionalFeatureSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$FeatureName
    )

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
    if (-not $feature) {
        Write-Log -Message "Optional feature '$FeatureName' not found. Skipping."
        return
    }

    if ($feature.State -eq 'Disabled') {
        Write-Log -Message "Optional feature '$FeatureName' is already disabled. Skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess($FeatureName, 'Disable-WindowsOptionalFeature')) {
        Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop | Out-Null
    }
}

# Disables a scheduled task when it exists and is currently enabled.
# --- FUNCTION: Disable-ScheduledTaskSafe --------------------------------------
# Purpose: Disables a scheduled task if it exists and is currently enabled.
# Impact: Reduces background telemetry and maintenance tasks.
# Risks: Some diagnostics or conveniences may no longer run automatically.

function Disable-ScheduledTaskSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$TaskIdentifier
    )

    $parts = $TaskIdentifier -split '\\'
    $taskName = $parts[-1]

    if ($parts.Length -gt 1) {
        $taskPath = '\\' + ($parts[0..($parts.Length - 2)] -join '\\') + '\\'
    } else {
        $taskPath = '\\'
    }

    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Log -Message "Scheduled task '$TaskIdentifier' not found. Skipping."
        return
    }

    if ($task.State -eq 'Disabled') {
        Write-Log -Message "Scheduled task '$TaskIdentifier' already disabled. Skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess($TaskIdentifier, 'Disable-ScheduledTask')) {
        Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop | Out-Null
    }
}

# Uninstalls OneDrive by running the official installer with uninstall flags.
# --- FUNCTION: Uninstall-OneDriveSafe -----------------------------------------
# Purpose: Attempts a clean removal of OneDrive (per-user binaries, processes,
#          and installed package) only when present.
# Impact: Removes OneDrive sync client and integrations.
# Risks: Files only in cloud won't sync locally; can reinstall later if needed.

function Uninstall-OneDriveSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    # --- SECTION: ONEDrive Uninstaller Paths -------------------------------------
# Paths to OneDrive setup executables for both 32/64-bit; used by removal routine.

$exePaths = @(
        (Join-Path -Path $env:SystemRoot -ChildPath 'SysWOW64\OneDriveSetup.exe'),
        (Join-Path -Path $env:SystemRoot -ChildPath 'System32\OneDriveSetup.exe')
    )

    $exePaths = $exePaths | Where-Object { Test-Path $_ }

    if (-not $exePaths) {
        Write-Log -Message 'OneDrive installer was not located. It may already be removed.'
        return
    }

    foreach ($exe in $exePaths) {
        if ($PSCmdlet.ShouldProcess($exe, 'Uninstall OneDrive')) {
            Start-Process -FilePath $exe -ArgumentList '/uninstall', '/quiet' -Wait -ErrorAction Stop
        }
    }

    Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.Name, 'Stop-Process')) {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not $PSVersionTable.PSVersion) {
    Write-Log -Level 'ERROR' -Message 'Unable to determine PowerShell version. Exiting.'
    return
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Log -Level 'ERROR' -Message "PowerShell 5.0 or higher is required. Current version: $($PSVersionTable.PSVersion)"
    return
}

if (-not (Test-Path Env:OS) -or $env:OS -ne 'Windows_NT') {
    Write-Log -Level 'ERROR' -Message 'This script can only be executed on Windows.'
    return
}

if (-not (Test-IsAdministrator)) {
    Write-Log -Level 'ERROR' -Message 'Administrator privileges are required. Please re-run PowerShell as Administrator.'
    return
}

Write-Log -Message 'Starting Windows de-bloat routine (profile 3).'

# --- SECTION: AppX Packages to Remove ----------------------------------------
# List of consumer/bundled Microsoft Store apps slated for removal to declutter.
# Safe: Removes per-user app packages; system remains stable; reinstallable later.

$appsToRemove = @(
    'Microsoft.3DBuilder',
    'Microsoft.BingFinance',
    'Microsoft.BingNews',
    'Microsoft.BingWeather',
    'Microsoft.DesktopAppInstaller',
    'Microsoft.GetHelp',
    'Microsoft.Getstarted',
    'Microsoft.Microsoft3DViewer',
    'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.MicrosoftStickyNotes',
    'Microsoft.MixedReality.Portal',
    'Microsoft.Office.OneNote',
    'Microsoft.People',
    'Microsoft.SkypeApp',
    'Microsoft.Tips',
    'Microsoft.Xbox.TCUI',
    'Microsoft.XboxApp',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxSpeechToTextOverlay',
    'Microsoft.YourPhone',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo'
)

# --- EXECUTION: AppX Removal Block ------------------------------------------
# Runs only if -SkipAppxPackages is NOT provided.
if (-not $SkipAppxPackages) {
    Write-Log -Message 'Removing bundled AppX packages...'
    foreach ($app in $appsToRemove) {
        Invoke-Safely -Description "AppX cleanup for '$app'" -Action { Remove-AppxPackageSafe -PackageName $app }
    }
} else {
    Write-Log -Message 'Skipping AppX package removal as requested.'
}

# --- SECTION: Optional Windows Features to Disable ---------------------------
# Legacy/rare features (PowerShell v2, XPS, Fax, WCF) disabled to reduce surface.

$featuresToDisable = @(
    'MicrosoftWindowsPowerShellV2',
    'MicrosoftWindowsPowerShellV2Root',
    'Printing-XPSServices-Features',
    'WorkFolders-Client',
    'FaxServicesClientPackage',
    'WCF-Services45'
)

# --- EXECUTION: Optional Feature Disable Block -------------------------------
# Runs only if -SkipOptionalFeatures is NOT provided.
if (-not $SkipOptionalFeatures) {
    Write-Log -Message 'Disabling optional Windows features...'
    foreach ($feature in $featuresToDisable) {
        Invoke-Safely -Description "Disable optional feature '$feature'" -Action { Disable-OptionalFeatureSafe -FeatureName $feature }
    }
} else {
    Write-Log -Message 'Skipping optional feature removal as requested.'
}

# --- SECTION: Scheduled Tasks to Disable -------------------------------------
# Telemetry/CEIP and background update tasks disabled to reduce data collection.

$scheduledTasksToDisable = @(
    'Microsoft\\Office\\OfficeTelemetryAgentFallBack2016',
    'Microsoft\\Office\\OfficeTelemetryAgentLogOn2016',
    'Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser',
    'Microsoft\\Windows\\Application Experience\\ProgramDataUpdater',
    'Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator',
    'Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip',
    'Microsoft\\Windows\\Maps\\MapsUpdateTask',
    'Microsoft\\XblGameSave\\XblGameSaveTask'
)

# --- EXECUTION: Scheduled Task Disable Block ---------------------------------
# Runs only if -SkipScheduledTasks is NOT provided.
if (-not $SkipScheduledTasks) {
    Write-Log -Message 'Disabling scheduled tasks...'
    foreach ($task in $scheduledTasksToDisable) {
        Invoke-Safely -Description "Disable scheduled task '$task'" -Action { Disable-ScheduledTaskSafe -TaskIdentifier $task }
    }
} else {
    Write-Log -Message 'Skipping scheduled task updates as requested.'
}

# --- EXECUTION: OneDrive Removal Block ---------------------------------------
# Runs only if -SkipOneDriveRemoval is NOT provided.
if (-not $SkipOneDriveRemoval) {
    Write-Log -Message 'Attempting to remove OneDrive...'
    Invoke-Safely -Description 'OneDrive removal' -Action { Uninstall-OneDriveSafe }
} else {
    Write-Log -Message 'Skipping OneDrive removal as requested.'
}

Write-Log -Message 'Windows de-bloat routine completed.'