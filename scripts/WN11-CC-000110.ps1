<#
.SYNOPSIS
    Enforces or disables the system policy to prevent printing over HTTP.

.DESCRIPTION
    This script modifies the 'DisableHTTPPrinting' registry key to comply with DISA STIG WN11-CC-000110.
    Disabling HTTP printing reduces the attack surface by preventing internet-based print job redirection.

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
    STIG-ID         : WN11-CC-000110

.LINK
    https://stigaview.com/products/win11/v2r1/WN11-CC-000110/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. :

.PARAMETER Enable
    Use `$true` to disable HTTP printing (compliant).
    Use `$false` to enable HTTP printing (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-CC-000110.ps1 -Enable $true
#>

# Define script parameter for enabling/disabling HTTP printing
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to disable HTTP printing (compliant), `$false` to enable (non-compliant)")]
    [bool]$Enable
)

# Function to set DisableHTTPPrinting
function Set-DisableHTTPPrinting {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $valueName = "DisableHTTPPrinting"
    # Set value: 1 = block (compliant), 0 = allow (non-compliant)
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

# Execute the configuration with user input
Set-DisableHTTPPrinting -State:$Enable
