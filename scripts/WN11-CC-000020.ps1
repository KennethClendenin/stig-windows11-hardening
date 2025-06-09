<#
.SYNOPSIS
    Enforces or removes IPv6 source routing protection by setting the appropriate registry key.

.DESCRIPTION
    This script configures the registry setting to prevent IPv6 source routing, a method that could be
    abused for spoofing or redirecting traffic. Setting the value to 2 disables source routing entirely.

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
    STIG-ID         : WN11-CC-000020

.LINK
    https://stigaview.com/products/win11/v2r3/WN11-CC-000020/
    
.TESTED ON
    Date(s) Tested  :
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. :

.PARAMETER Enable
    Use `$true` to block IPv6 source routing (compliant/highest protection).
    Use `$false` to allow IPv6 source routing (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-CC-000020.ps1 -Enable $false
#>

# Define script parameter for enabling/disabling IPv6 source routing
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to enable IPv6 source routing protection (compliant), or `$false` to disable it (non-compliant)")]
    [bool]$Enable
)

# Function to set IPv6 source routing protection
function Set-IPv6SourceRoutingProtection {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $valueName = "DisableIpSourceRouting"
    # Set value: 2 = block (compliant), 0 = allow (non-compliant)
    $desiredValue = if ($State) { 2 } else { 0 }  # $true = compliant (2), $false = non-compliant (0)

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
Set-IPv6SourceRoutingProtection -State:$Enable
