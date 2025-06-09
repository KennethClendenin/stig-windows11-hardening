<#
.SYNOPSIS
    Enforces or disables secure RPC communication for Remote Desktop Session Host.

.DESCRIPTION
    This script sets the 'fEncryptRPCTraffic' registry value to require (or not require) secure RPC communication 
    for Remote Desktop Session Host. Enabling secure RPC mitigates man-in-the-middle (MITM) attacks.

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
    STIG-ID         : WN11-CC-000285

.LINK
    https://stigaview.com/products/win11/v2r3/WN11-CC-000285/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.PARAMETER Enable
    Use `$true` to enforce secure RPC (compliant).
    Use `$false` to allow unsecure RPC (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-CC-000285.ps1 -Enable $true

#>

# Define script parameter for enabling/disabling secure RPC
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true to enable secure RPC (compliant), or `$false to disable (non-compliant)")]
    [bool]$Enable
)

# Function to set secure RPC communication
function Set-SecureRPCCommunication {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $valueName = "fEncryptRPCTraffic"
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
Set-SecureRPCCommunication -State:$Enable
