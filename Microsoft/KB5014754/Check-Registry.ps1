function Get-KDCRegistryStatus {
    # Define the registry path
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
    
    # Get current date for output file
    $date = Get-Date -Format "yyyyMMdd-HHmmss"
    $outputFile = "DC_Registry_Check_$date.txt"

    try {
        # Get registry values
        $registryValues = Get-ItemProperty -Path $registryPath -ErrorAction Stop
        
        # Check StrongCertificateBindingEnforcement
        $strongBinding = $registryValues.StrongCertificateBindingEnforcement
        $backdatingComp = $registryValues.CertificateBackdatingCompensation

        # Prepare results
        $results = @"
=====================================================
DC Certificate Authentication Registry Check
Date: $(Get-Date)
Server: $env:COMPUTERNAME
=====================================================

StrongCertificateBindingEnforcement Status:
------------------------------------------
Current Value: $strongBinding
Status: $(switch ($strongBinding) {
    0 {"WARNING: Disabled - All security enhancements disabled (NOT RECOMMENDED)"}
    1 {"Audit Mode - Allows authentication with warnings"}
    2 {"Enforcement Mode - Required for Feb 2025 compliance"}
    $null {"WARNING: Not configured - Will default to Enforcement Mode in Feb 2025"}
    default {"WARNING: Unknown value"}
})

CertificateBackdatingCompensation Status:
----------------------------------------
Current Value: $backdatingComp
Status: $(if ($null -eq $backdatingComp) {
    "Not configured - Default 10 minutes backdating"
} else {
    "Configured - Approximately $([math]::Round($backdatingComp/31536000, 1)) years backdating"
})

Recommendations:
---------------
$(switch ($strongBinding) {
    0 {"CRITICAL: Value 0 is not recommended. Change to 1 for testing or 2 for enforcement."}
    1 {"ADVISORY: Current setting is good for testing. Must be changed to 2 before February 2025."}
    2 {"COMPLIANT: Current setting meets February 2025 requirements."}
    $null {"WARNING: Registry key not set. Configure to 1 for testing or 2 for enforcement."}
    default {"ERROR: Unknown value detected. Please verify configuration."}
})
"@

        # Output to console and file
        $results
        $results | Out-File -FilePath $outputFile
        Write-Host "`nResults have been saved to: $outputFile"

    }
    catch {
        Write-Host "Error accessing registry: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Run the check
Get-KDCRegistryStatus