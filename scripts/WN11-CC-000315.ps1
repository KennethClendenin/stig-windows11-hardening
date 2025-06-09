<#
.SYNOPSIS
    Disables the "Always install with elevated privileges" policy.

.DESCRIPTION
    This script sets the registry value 'AlwaysInstallElevated' under the HKLM hive to 0,
    preventing users from installing software with elevated privileges through Windows Installer.

.NOTES
    Author          : Kenneth Clendenin
    AI Contribution : Script generated with assistance from GitHub Copilot and OpenAI ChatGPT.
    Validation      : Final version reviewed, refined, and validated as functional based on Tenable scan results.
    LinkedIn        : https://www.linkedin.com/in/kenneth-clendenin/
    GitHub          : https://github.com/KennethClendenin
    Date Created    : 2025-06-04
    Last Modified   : 2025-06-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.LINK
    https://stigaview.com/products/win11/v2r1/WN11-CC-000315/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.PARAMETER Enable
    Use `$true` to disable elevated installs (compliant).
    Use `$false` to allow elevated installs (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-CC-000315.ps1 -Enable $false

#>

# Define script parameter for enabling/disabling AlwaysInstallElevated
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to disable elevated installs (compliant), or `$false` to allow elevated installs (non-compliant)")]
    [bool]$Enable
)

# Function to set AlwaysInstallElevated
function Set-AlwaysInstallElevated {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $valueName = "AlwaysInstallElevated"
    # Set value: 0 = disable (compliant), 1 = enable (non-compliant)
    $desiredValue = if ($State) { 0 } else { 1 }

    try {
        # Create registry path if it doesn't exist
        if (-not (Test-Path $registryPath)) {
            Write-Verbose "Registry path does not exist. Creating: $registryPath"
            New-Item -Path $registryPath -Force | Out-Null
        }

        # Get current value if it exists
        $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue

        # Set value if not already set
        if ($currentValue -ne $desiredValue) {
            Write-Host "Setting '$valueName' to $desiredValue (compliant: $($State -eq $true))"
            Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord
        }
        else {
            Write-Host "'$valueName' is already set to $desiredValue. No changes made."
        }
    }
    catch {
        # Handle errors
        Write-Error "Failed to set registry key: $_"
    }
}

# Execute remediation with user input
Set-AlwaysInstallElevated -State:$Enable
