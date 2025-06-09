<#
.SYNOPSIS
    Enforces or modifies the Application Event Log maximum size to meet or exceed 32768 KB.

.DESCRIPTION
    This script sets the 'MaxSize' registry value for the Application Event Log to 32768 KB (32 MB) or more.
    This ensures logs retain more entries and comply with audit record retention standards.

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
    STIG-ID         : WN11-AU-000500

.LINK 
    https://stigaview.com/products/win11/v2r2/WN11-AU-000500/ 

.TESTED ON
    Date(s) Tested  :
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.PARAMETER Enable
    Use `$true` to enforce the minimum 32MB size (compliant).
    Use `$false` to reduce the size to 1024 KB (non-compliant for test/demo).

.EXAMPLE
    PS C:\> .\WN11-AU-000500.ps1 -Enable $true
#>

# Script parameter: $Enable determines if the log size should be compliant (32768 KB) or non-compliant/test (1024 KB)
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to set Application log size to >= 32768 KB (compliant), `$false` to reduce to 1024 KB (non-compliant/test only)")]
    [bool]$Enable
)

# Function to set the Application Event Log maximum size
function Set-ApplicationLogMaxSize {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define the registry path and value name for the Application log size
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
    $valueName = "MaxSize"
    # Set desired value based on $State: 32768 KB if true (compliant), 1024 KB if false (test)
    $desiredValue = if ($State) { 32768 } else { 1024 }

    try {
        # Check if the registry path exists; create it if it does not
        if (-not (Test-Path -Path $registryPath)) {
            Write-Verbose "Registry path not found. Creating: $registryPath"
            New-Item -Path $registryPath -Force | Out-Null
        }

        # Get the current value of MaxSize (if it exists)
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

        # If the current value is not what we want, set it to the desired value
        if ($currentValue -ne $desiredValue) {
            Write-Host "[$($valueName)] Setting Application Event Log max size to $desiredValue KB (compliant: $($State -eq $true))"
            Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord -Force
        }
        else {
            # If already set, inform the user
            Write-Host "[$($valueName)] Value is already set to $desiredValue KB. No changes made."
        }
    }
    catch {
        # Handle any errors that occur during the registry operation
        Write-Error "[$($valueName)] Failed to set registry value: $_"
    }
}

# Call the function, passing the script parameter $Enable as $State
Set-ApplicationLogMaxSize -State:$Enable
