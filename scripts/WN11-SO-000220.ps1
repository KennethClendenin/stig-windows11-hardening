<#
.SYNOPSIS
    Enforces or removes the minimum NTLM SSP-based server session security requirements.

.DESCRIPTION
    This script sets the 'NTLMMinServerSec' registry value to require NTLMv2 session security and 128-bit encryption.
    This hardens the system against older and weaker authentication attempts over RPC.

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
    STIG-ID         : WN11-SO-000220

.LINK
    https://stigaview.com/products/win11/v1r6/WN11-SO-000220/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.PARAMETER Enable
    Use `$true` to require secure NTLM SSP server settings (compliant).
    Use `$false` to reduce security settings (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-SO-000220.ps1 -Enable $true
#>

# Define script parameter for enabling/disabling secure NTLM SSP server settings
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to enable secure NTLM SSP server settings (compliant), `$false` to revert (non-compliant)")]
    [bool]$Enable
)

# Function to set NTLM SSP server session security requirements
function Set-NTLMMinServerSec {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "NTLMMinServerSec"
    # Set value: 0x20080000 = require NTLMv2 session security and 128-bit encryption (compliant)
    #            0x00000000 = no minimum security (non-compliant)
    $desiredValue = if ($State) { 0x20080000 } else { 0x00000000 }

    try {
        # Create registry path if it doesn't exist
        if (-not (Test-Path $registryPath)) {
            Write-Verbose "Creating registry path: $registryPath"
            New-Item -Path $registryPath -Force | Out-Null
        }

        # Get current value if it exists
        $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue

        # Set value if not already set
        if ($currentValue -ne $desiredValue) {
            Write-Host ("Setting '{0}' to 0x{1:X8} (compliant: {2})" -f $valueName, $desiredValue, ($State -eq $true))
            Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord
        }
        else {
            Write-Host ("'{0}' already set to 0x{1:X8}. No changes made." -f $valueName, $desiredValue)
        }
    }
    catch {
        # Handle errors
        Write-Error "Failed to apply registry setting: $_"
    }
}

# Execute the remediation with user input
Set-NTLMMinServerSec -State:$Enable
