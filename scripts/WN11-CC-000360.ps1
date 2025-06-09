<#
.SYNOPSIS
    Disables Digest authentication for the Windows Remote Management (WinRM) client.

.DESCRIPTION
    Digest authentication is considered less secure and subject to man-in-the-middle attacks. 
    This script disables Digest authentication on the WinRM client by setting the AllowDigest registry value to 0.

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
    STIG-ID         : WN11-CC-000360

.LINK
    https://stigaview.com/products/win11/v2r2/WN11-CC-000360/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.PARAMETER Enable
    Use `$true` to disable Digest authentication (compliant).
    Use `$false` to enable Digest authentication (non-compliant for test/demo).


.EXAMPLE
    PS C:\> .\WN11-CC-000360.ps1 -Enable $true
#>

# Define script parameter for enabling/disabling Digest authentication
param (
    [Parameter(Mandatory = $true, HelpMessage = "Use `$true` to disable Digest authentication (compliant), or `$false` to enable it (non-compliant)")]
    [bool]$Enable
)

# Function to set WinRM Digest authentication
function Set-WinRMDigestAuth {
    param (
        # Function parameter: $State, passed from script parameter $Enable
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    # Define registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    $valueName = "AllowDigest"
    # Set value: 0 = disable (compliant), 1 = enable (non-compliant)
    $desiredValue = if ($State) { 0 } else { 1 }

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
        Write-Error "Failed to apply registry setting: $_"
    }
}

# Execute the remediation with user input
Set-WinRMDigestAuth -State:$Enable
