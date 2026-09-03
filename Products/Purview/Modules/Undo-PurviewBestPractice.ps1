#requires -Version 7.0
<#
.SYNOPSIS
    Reverses the Microsoft Purview Best Practice deployment.

.DESCRIPTION
    Removes or reverts all changes made by Deploy-PurviewBestPractice.ps1:
    
    - Removes sensitivity labels created by the toolkit
    - Removes DLP policies and rules created by the toolkit
    - Removes retention policies created by the toolkit
    - Removes AI governance Copilot DLP policies created by the toolkit
    - Reverts tenant settings (audit log, AIP integration, label co-authoring, container labels)

    This script is a DESTRUCTIVE operation and should be run with caution. It will:
    - PERMANENTLY DELETE sensitivity labels (and all encrypted content access patterns change)
    - PERMANENTLY DELETE DLP policies (and all blocked external sharing restrictions)
    - REMOVE retention policies (and allow deleted items to be purged)
    - DISABLE container labels on Microsoft 365 Groups and Teams

    Idempotent: the script checks for toolkit-managed tags before removing objects
    and can be safely re-run.

.PARAMETER TenantAdminUpn
    UPN of the tenant administrator (or partner GDAP admin) used for sign-in.

.PARAMETER SharePointAdminUrl
    Optional override for the SharePoint admin centre URL.

.PARAMETER DelegatedOrganization
    Customer tenant primary domain when running as a partner via GDAP.

.PARAMETER ConfigPath
    Path to a custom PurviewConfig.psd1. Defaults to .\Config\PurviewConfig.psd1.

.PARAMETER RemoveLabels
    Remove sensitivity labels created by the toolkit.

.PARAMETER RemoveDLP
    Remove DLP policies and rules created by the toolkit.

.PARAMETER RemoveRetention
    Remove retention policies created by the toolkit.

.PARAMETER RemoveAIGovernance
    Remove AI governance Copilot DLP policies created by the toolkit.

.PARAMETER RevertTenantSettings
    Revert tenant-wide settings (audit, AIP integration, container labels, label co-authoring).
    WARNING: label co-authoring reversion requires PowerShell-only and may not be fully reversible.

.PARAMETER RemoveAll
    Remove/revert all changes (equivalent to passing all Remove* and Revert* flags).

.PARAMETER NonInteractive
    Skip confirmation prompts (use with caution in CI/automation).

.PARAMETER AutoInstallModules
    Auto-install any missing PowerShell modules without prompting.

.EXAMPLE
    # Remove labels and DLP only
    .\Undo-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com `
        -RemoveLabels -RemoveDLP

.EXAMPLE
    # Remove everything
    .\Undo-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com `
        -RemoveAll

.NOTES
    * Backup your tenant configuration before running this script.
    * Sensitivity label removal is PERMANENT. Users will lose access to encrypted
      content protected by those labels.
    * Changes can take up to 24 hours to propagate.
    * This script uses the same managed-by tag as Deploy-PurviewBestPractice.ps1
      to identify objects to remove.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $TenantAdminUpn,

    [Parameter()]
    [string] $SharePointAdminUrl,

    [Parameter()]
    [string] $DelegatedOrganization,

    [Parameter()]
    [string] $ConfigPath,

    [Parameter()]
    [switch] $RemoveLabels,

    [Parameter()]
    [switch] $RemoveDLP,

    [Parameter()]
    [switch] $RemoveRetention,

    [Parameter()]
    [switch] $RemoveAIGovernance,

    [Parameter()]
    [switch] $RevertTenantSettings,

    [Parameter()]
    [switch] $RemoveAll,

    [Parameter()]
    [switch] $NonInteractive,

    [Parameter()]
    [switch] $AutoInstallModules
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference   = 'None'

# Get script root for module imports
$scriptRoot = Split-Path -Parent $PSCommandPath
$moduleRoot = Split-Path -Parent $scriptRoot  # Go up one level from Modules/ to Products/Purview/
$moduleRoot = Join-Path $moduleRoot 'Modules'

# Load config
if (-not $ConfigPath) {
    $ConfigPath = Join-Path (Split-Path -Parent $scriptRoot) 'Config\PurviewConfig.psd1'
}
if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}
$config = Import-PowerShellDataFile -Path $ConfigPath

# Normalize flags: -RemoveAll enables all removal operations
if ($RemoveAll) {
    $RemoveLabels        = $true
    $RemoveDLP           = $true
    $RemoveRetention     = $true
    $RemoveAIGovernance  = $true
    $RevertTenantSettings = $true
}

# If no removal flags are set, show help
if (-not ($RemoveLabels -or $RemoveDLP -or $RemoveRetention -or $RemoveAIGovernance -or $RevertTenantSettings)) {
    Write-Host @"
No removal operations selected. Pass one or more of:
  -RemoveLabels              Remove sensitivity labels
  -RemoveDLP                 Remove DLP policies
  -RemoveRetention           Remove retention policies
  -RemoveAIGovernance        Remove AI governance Copilot DLP policies
  -RevertTenantSettings      Revert tenant-wide settings
  -RemoveAll                 Equivalent to passing all above flags

Examples:
  .\Undo-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.com -RemoveAll
  .\Undo-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.com -RemoveLabels -RemoveDLP
"@
    exit 0
}

# Connect to services
Write-Host "`n--- Connecting to services ---" -ForegroundColor White

$connectScript = Join-Path $moduleRoot 'Connect-PurviewServices.ps1'
if (-not (Test-Path $connectScript)) {
    throw "Connect script not found: $connectScript"
}

$connectArgs = @{ TenantAdminUpn = $TenantAdminUpn }
if ($RemoveLabels -or $RemoveDLP -or $RemoveRetention) {
    $connectArgs['NeedsSharePoint'] = $true
}
if ($SharePointAdminUrl) { $connectArgs['SharePointAdminUrl'] = $SharePointAdminUrl }
if ($DelegatedOrganization) { $connectArgs['DelegatedOrganization'] = $DelegatedOrganization }
if ($RevertTenantSettings) { $connectArgs['ConnectGraph'] = $true }
if ($AutoInstallModules) { $connectArgs['AutoInstallModules'] = $true }
if ($NonInteractive) { $connectArgs['NonInteractive'] = $true }

& $connectScript @connectArgs | Out-Null

$tag = $config.ManagedByTag

# Display confirmation banner
$banner = @"

==============================================================================
  UNDO: Microsoft Purview Best Practice Deployment
  *** WARNING: DESTRUCTIVE OPERATION ***
==============================================================================

  This will PERMANENTLY REMOVE/REVERT:
"@

if ($RemoveLabels) { $banner += "`n    [X] Sensitivity labels created by the toolkit" }
if ($RemoveDLP) { $banner += "`n    [X] DLP policies and rules created by the toolkit" }
if ($RemoveRetention) { $banner += "`n    [X] Retention policies created by the toolkit" }
if ($RemoveAIGovernance) { $banner += "`n    [X] AI governance Copilot DLP policies created by the toolkit" }
if ($RevertTenantSettings) { $banner += "`n    [X] Tenant-wide settings (audit, AIP, container labels, co-authoring)" }

$banner += @"

  Impacts:
  - Encrypted documents using removed labels will become inaccessible
  - External sharing restrictions will be lifted
  - Retention enforcement will stop
  - Sensitive content may no longer be protected by Copilot DLP

  This operation CANNOT BE FULLY UNDONE. Ensure you have reviewed the
  configuration and have backups before proceeding.

==============================================================================
"@

Write-Host $banner -ForegroundColor Red

if (-not $WhatIfPreference -and -not $NonInteractive) {
    $confirm = Read-Host "I understand the risks and want to proceed. Type 'yes' to continue"
    if ($confirm -ne 'yes') {
        Write-Host "Undo operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

function Test-Owned {
    param($Object, [string] $Tag)
    if (-not $Object) { return $false }
    $desc = if ($Object.PSObject.Properties.Name -contains 'Comment') { $Object.Comment }
            elseif ($Object.PSObject.Properties.Name -contains 'Description') { $Object.Description }
            else { '' }
    return ($desc -and $desc -like "*$Tag*")
}

# ============================================================================
# REMOVE LABELS
# ============================================================================
if ($RemoveLabels) {
    Write-Host "`n--- Removing Sensitivity Labels ---" -ForegroundColor White
    
    try {
        $allLabels = @(Get-Label -ErrorAction SilentlyContinue)
        $toolkitLabels = @($allLabels | Where-Object { Test-Owned $_ $tag })
        
        if ($toolkitLabels.Count -eq 0) {
            Write-Host "  No toolkit-managed labels found." -ForegroundColor DarkGray
        } else {
            Write-Host "  Found $($toolkitLabels.Count) toolkit-managed label(s) to remove:" -ForegroundColor Yellow
            
            foreach ($lbl in $toolkitLabels) {
                Write-Host "    - $($lbl.DisplayName)" -ForegroundColor Yellow
                
                if ($PSCmdlet.ShouldProcess($lbl.DisplayName, 'Remove-Label')) {
                    try {
                        Remove-Label -Identity $lbl.Guid -Confirm:$false -ErrorAction Stop
                        Write-Host "      [REMOVED]" -ForegroundColor Green
                    } catch {
                        Write-Warning "      Failed to remove label: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error removing labels: $($_.Exception.Message)"
    }
}

# ============================================================================
# REMOVE DLP POLICIES
# ============================================================================
if ($RemoveDLP) {
    Write-Host "`n--- Removing DLP Policies ---" -ForegroundColor White
    
    try {
        $allPolicies = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
        $toolkitPolicies = @($allPolicies | Where-Object { Test-Owned $_ $tag })
        
        if ($toolkitPolicies.Count -eq 0) {
            Write-Host "  No toolkit-managed DLP policies found." -ForegroundColor DarkGray
        } else {
            Write-Host "  Found $($toolkitPolicies.Count) toolkit-managed DLP policy/ies to remove:" -ForegroundColor Yellow
            
            foreach ($policy in $toolkitPolicies) {
                Write-Host "    - $($policy.Name)" -ForegroundColor Yellow
                
                if ($PSCmdlet.ShouldProcess($policy.Name, 'Remove-DlpCompliancePolicy')) {
                    try {
                        # Rules are auto-deleted when the policy is removed
                        Remove-DlpCompliancePolicy -Identity $policy.Guid -Confirm:$false -ErrorAction Stop
                        Write-Host "      [REMOVED] (rules auto-deleted)" -ForegroundColor Green
                    } catch {
                        Write-Warning "      Failed to remove policy: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error removing DLP policies: $($_.Exception.Message)"
    }
}

# ============================================================================
# REMOVE RETENTION POLICIES
# ============================================================================
if ($RemoveRetention) {
    Write-Host "`n--- Removing Retention Policies ---" -ForegroundColor White
    
    try {
        $allPolicies = @(Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue)
        $toolkitPolicies = @($allPolicies | Where-Object { Test-Owned $_ $tag })
        
        if ($toolkitPolicies.Count -eq 0) {
            Write-Host "  No toolkit-managed retention policies found." -ForegroundColor DarkGray
        } else {
            Write-Host "  Found $($toolkitPolicies.Count) toolkit-managed retention policy/ies to remove:" -ForegroundColor Yellow
            
            foreach ($policy in $toolkitPolicies) {
                Write-Host "    - $($policy.Name)" -ForegroundColor Yellow
                
                if ($PSCmdlet.ShouldProcess($policy.Name, 'Remove-RetentionCompliancePolicy')) {
                    try {
                        # Rules are auto-deleted when the policy is removed
                        Remove-RetentionCompliancePolicy -Identity $policy.Identity -Confirm:$false -ErrorAction Stop
                        Write-Host "      [REMOVED] (rules auto-deleted)" -ForegroundColor Green
                    } catch {
                        Write-Warning "      Failed to remove retention policy: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error removing retention policies: $($_.Exception.Message)"
    }
}

# ============================================================================
# REMOVE AI GOVERNANCE POLICIES
# ============================================================================
if ($RemoveAIGovernance) {
    Write-Host "`n--- Removing AI Governance DLP Policies ---" -ForegroundColor White
    
    try {
        $allPolicies = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
        # AI governance policies typically have specific naming patterns (AI_* or Copilot*)
        $aiPolicies = @($allPolicies | Where-Object { 
            $_.Name -like 'AI_*' -or $_.Name -like '*Copilot*' -and (Test-Owned $_ $tag)
        })
        
        if ($aiPolicies.Count -eq 0) {
            Write-Host "  No toolkit-managed AI governance policies found." -ForegroundColor DarkGray
        } else {
            Write-Host "  Found $($aiPolicies.Count) toolkit-managed AI governance policy/ies to remove:" -ForegroundColor Yellow
            
            foreach ($policy in $aiPolicies) {
                Write-Host "    - $($policy.Name)" -ForegroundColor Yellow
                
                if ($PSCmdlet.ShouldProcess($policy.Name, 'Remove-DlpCompliancePolicy')) {
                    try {
                        Remove-DlpCompliancePolicy -Identity $policy.Guid -Confirm:$false -ErrorAction Stop
                        Write-Host "      [REMOVED]" -ForegroundColor Green
                    } catch {
                        Write-Warning "      Failed to remove AI policy: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error removing AI governance policies: $($_.Exception.Message)"
    }
}

# ============================================================================
# REVERT TENANT SETTINGS
# ============================================================================
if ($RevertTenantSettings) {
    Write-Host "`n--- Reverting Tenant Settings ---" -ForegroundColor White
    
    # Audit Log (note: reverting audit is less critical, usually left on)
    Write-Host "  Audit Log: Leaving enabled (reverting would silence important audit trails)" -ForegroundColor DarkGray
    
    # AIP Integration in SharePoint
    Write-Host "  SharePoint AIP Integration: Disabling..." -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess('SharePoint Online', 'Disable AIP integration')) {
        try {
            Set-SPOTenant -EnableAIPIntegration $false -WarningAction SilentlyContinue -ErrorAction Stop
            Write-Host "    [DISABLED]" -ForegroundColor Green
        } catch {
            Write-Warning "    Failed to disable AIP integration: $($_.Exception.Message)"
        }
    }
    
    # Container Labels (Group.Unified EnableMIPLabels)
    Write-Host "  Container Labels (Group.Unified): Disabling..." -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess('Group.Unified directory setting', 'Disable EnableMIPLabels')) {
        try {
            $existing = Get-MgBetaDirectorySetting -ErrorAction SilentlyContinue |
                Where-Object { $_.TemplateId -and ($_.Values.Name -contains 'EnableMIPLabels') }
            
            if ($existing) {
                $newValues = foreach ($v in $existing.Values) {
                    if ($v.Name -eq 'EnableMIPLabels') {
                        @{ name = $v.Name; value = 'False' }
                    } else {
                        @{ name = $v.Name; value = $v.Value }
                    }
                }
                Update-MgBetaDirectorySetting -DirectorySettingId $existing.Id `
                    -BodyParameter @{ values = $newValues } -ErrorAction Stop | Out-Null
                Write-Host "    [DISABLED]" -ForegroundColor Green
            } else {
                Write-Host "    [Already disabled or not configured]" -ForegroundColor DarkGray
            }
        } catch {
            Write-Warning "    Failed to disable container labels: $($_.Exception.Message)"
        }
    }
    
    # Label Co-Authoring (this is one-way and cannot be fully disabled)
    Write-Host "  Label Co-Authoring (Set-PolicyConfig): CANNOT FULLY REVERT" -ForegroundColor Yellow
    Write-Host "    Reason: This is a one-way tenant switch. Once enabled, disabling it" -ForegroundColor DarkGray
    Write-Host "    removes the new metadata location and users lose label info on" -ForegroundColor DarkGray
    Write-Host "    unencrypted Office files. Manual remediation required via Support." -ForegroundColor DarkGray
}

Write-Host "`n--- Undo Complete ---" -ForegroundColor Green
Write-Host "Summary: Toolkit-managed objects have been removed/reverted." -ForegroundColor Green
Write-Host "Note: Changes can take up to 24 hours to propagate." -ForegroundColor DarkYellow
