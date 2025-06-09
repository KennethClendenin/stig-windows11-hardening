<#
.SYNOPSIS
    Enables or disables Enhanced Anti-Spoofing for facial recognition on supported Windows 11 systems.

.DESCRIPTION
    This script configures the registry setting that enforces enhanced anti-spoofing for Windows Hello facial recognition.
    This provides better protection against facial spoofing attacks on compatible hardware.

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
    STIG-ID         : WN11-CC-000195

.LINK
    https://stigaview.com/products/win11/v2r3/WN11-CC-000195/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.PARAMETER Enable
    Use `$true` to enable Enhanced Anti-Spoofing (compliant).
    Use `$false` to disable it (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-CC-000195.ps1 -Enable $true
#>

# Define script parameter for enabling/disabling Enhanced Anti-Spoofing
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to enable Enhanced Anti-Spoofing (compliant), or `$false` to disable it (non-compliant)")]
    [bool]$Enable
)

# Function to set Enhanced Anti-Spoofing
function Set-EnhancedAntiSpoofing {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
    $valueName = "EnhancedAntiSpoofing"
    # Set value: 1 = enable (compliant), 0 = disable (non-compliant)
    $desiredValue = if ($State) { 1 } else { 0 }

    try {
        # Create registry path if it doesn't exist
        if (-not (Test-Path $registryPath)) {
            Write-Verbose "Registry path does not exist. Creating: $registryPath"
            New-Item -Path $registryPath -Force | Out-Null
        }

        # Get current value if it exists
        $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue

        # Set value if not already set
        if ($currentValue -ne $desiredValue) {
            Write-Host ("Setting '{0}' to {1} (compliant: {2})" -f $valueName, $desiredValue, ($State -eq $true))
            Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord
        }
        else {
            Write-Host ("'{0}' is already set to {1}. No changes made." -f $valueName, $desiredValue)
        }
    }
    catch {
        # Handle errors
        Write-Error "Failed to set registry key: $_"
    }
}

# Execute remediation with user input
Set-EnhancedAntiSpoofing -State:$Enable
