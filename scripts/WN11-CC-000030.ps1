<#
.SYNOPSIS
    Enforces or removes the configuration to block ICMP redirects from overriding OSPF routes.

.DESCRIPTION
    This script sets the 'EnableICMPRedirect' registry value under the TCP/IP parameters key.
    Setting this to 0 prevents ICMP redirects from modifying routing behavior, which helps preserve
    the integrity of OSPF routing and avoids potential MITM traffic rerouting.

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
    STIG-ID         : WN11-CC-000030

.LINK
    https://stigaview.com/products/win11/v2r1/WN11-CC-000030/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.PARAMETER Enable
    Use `$true` to block ICMP redirects (compliant).
    Use `$false` to allow ICMP redirects (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-CC-000030.ps1 -Enable $false
#>

# Define script parameter for enabling/disabling ICMP redirects
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to block ICMP redirects (compliant), or `$false` to allow ICMP redirects (non-compliant)")]
    [bool]$Enable
)

# Function to set ICMP redirect override
function Set-ICMPRedirectOverride {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $valueName = "EnableICMPRedirect"
    # Set value: 0 = block (compliant), 1 = allow (non-compliant)
    $desiredValue = if ($State) { 0 } else { 1 }

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
Set-ICMPRedirectOverride -State:$Enable
