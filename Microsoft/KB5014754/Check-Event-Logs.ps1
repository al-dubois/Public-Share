<#
.SYNOPSIS
    Analyzes certificate authentication events and generates detailed reports for KB5014754-related issues.

.DESCRIPTION
    This script checks for certificate authentication events (Event IDs 39, 40, 41) related to KB5014754 
    and generates detailed reports in CSV and optionally HTML format. It provides remediation steps and 
    recommendations based on the findings.

.PARAMETER Days
    Number of days to look back for events. Default is 1 day.

.PARAMETER StartDate
    Specific start date to begin event search (format: yyyy-MM-dd).

.PARAMETER EndDate
    Specific end date to end event search (format: yyyy-MM-dd).

.PARAMETER OutputPath
    Path where the report files will be saved. Default is current directory with timestamp.

.PARAMETER HTML
    Switch to generate an HTML report in addition to CSV.

.PARAMETER Quiet
    Switch to suppress console output.

.PARAMETER TestMode
    Switch to run in test mode with generated sample data.

.PARAMETER TestEventCount
    Number of test events to generate in test mode. Default is 10.

.EXAMPLE
    # Check last 24 hours and generate both CSV and HTML reports
    .\Check-Certificate-Events.ps1 -HTML

.EXAMPLE
    # Check last 7 days with custom output path
    .\Check-Certificate-Events.ps1 -Days 7 -OutputPath "C:\Reports\CertAudit"

.EXAMPLE
    # Check specific date range
    .\Check-Certificate-Events.ps1 -StartDate "2024-01-01" -EndDate "2024-01-31" -HTML

.EXAMPLE
    # Run in test mode with 20 sample events
    .\Check-Certificate-Events.ps1 -TestMode -TestEventCount 20 -HTML

.EXAMPLE
    # Silent execution with only CSV output
    .\Check-Certificate-Events.ps1 -Days 3 -Quiet
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$Days = "1",

    [Parameter(Mandatory=$false)]
    [string]$StartDate,

    [Parameter(Mandatory=$false)]
    [string]$EndDate,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\CertEvents_$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [Parameter(Mandatory=$false)]
    [switch]$HTML,

    [Parameter(Mandatory=$false)]
    [switch]$Quiet,

    [Parameter(Mandatory=$false)]
    [switch]$TestMode,

    [Parameter(Mandatory=$false)]
    [int]$TestEventCount = 10
)

# Function to generate test event data
function Get-TestEvents {
    param (
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$Count
    )

    $testUsers = @(
        "john.doe", "jane.smith", "bob.wilson", 
        "alice.johnson", "mike.brown", "sarah.davis"
    )
    $testDomains = @("contoso.com", "fabrikam.net", "acme.org")
    $testOUs = @("IT", "HR", "Finance", "Sales", "Marketing")
    
    $events = @()
    
    1..$Count | ForEach-Object {
        $eventId = @(39, 40, 41) | Get-Random
        $user = $testUsers | Get-Random
        $domain = $testDomains | Get-Random
        $ou = $testOUs | Get-Random
        $timeStamp = $StartTime.AddSeconds((New-TimeSpan -Start $StartTime -End $EndTime).TotalSeconds * (Get-Random -Minimum 0 -Maximum 100) / 100)
        
        $certSerial = (1..8 | ForEach-Object { "{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255) }) -join ''
        $thumbprint = (1..40 | ForEach-Object { "{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255) }) -join ''
        
        $eventData = [PSCustomObject]@{
            TimeStamp = $timeStamp
            EventID = $eventId
            EventType = switch ($eventId) {
                39 { "No strong certificate mapping found" }
                40 { "Certificate predates account" }
                41 { "User SID mismatch with certificate SID" }
            }
            User = "$user@$domain"
            CertSubject = "CN=$user,OU=$ou,DC=$($domain.Split('.')[0]),DC=$($domain.Split('.')[1])"
            CertIssuer = "CN=Enterprise-CA,DC=$($domain.Split('.')[0]),DC=$($domain.Split('.')[1])"
            SerialNumber = $certSerial
            Thumbprint = $thumbprint
        }
        $events += $eventData
    }
    
    return $events | Sort-Object TimeStamp
}

function Write-Output-Unless-Quiet {
    param([string]$Message, [string]$Color = "White")
    if (-not $Quiet) {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Get-RemediationSteps {
    param (
        [array]$Events,
        [int]$RegValue
    )
    
    $recommendations = @()
    
    # Registry recommendations
    switch ($RegValue) {
        0 { 
            $recommendations += @{
                Issue = "StrongCertificateBindingEnforcement set to 0 (Disabled)"
                Impact = "HIGH - All security enhancements are disabled"
                Action = "Change registry value to 1 for testing or 2 for enforcement. Value 0 is not recommended and disables all security enhancements."
                Command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -Value 1'
            }
        }
        $null { 
            $recommendations += @{
                Issue = "StrongCertificateBindingEnforcement not configured"
                Impact = "HIGH - Will default to Enforcement Mode in February 2025"
                Action = "Configure registry value to 1 for testing phase before enforcing"
                Command = 'New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -Value 1 -PropertyType DWORD'
            }
        }
        1 { 
            $recommendations += @{
                Issue = "Running in Audit Mode"
                Impact = "MEDIUM - Preparing for February 2025 deadline"
                Action = "Monitor events and plan to change to Enforcement Mode (value 2) before February 2025"
                Command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -Value 2'
            }
        }
    }

    # Event-specific recommendations
    $event39Count = ($Events | Where-Object EventID -eq 39).Count
    $event40Count = ($Events | Where-Object EventID -eq 40).Count
    $event41Count = ($Events | Where-Object EventID -eq 41).Count

    if ($event39Count -gt 0) {
        $recommendations += @{
            Issue = "No strong certificate mapping found ($event39Count events)"
            Impact = "HIGH - Certificates using weak mapping methods"
            Action = "Update to strong mapping methods (X509IssuerSerialNumber recommended). Example command to update user mapping:"
            Command = 'set-aduser "username" -replace @{altSecurityIdentities= "X509:<I>DC=com,DC=contoso,CN=CONTOSO-DC-CA<SR>1200000000AC11000000002B"}'
        }
    }

    if ($event40Count -gt 0) {
        $recommendations += @{
            Issue = "Certificates predate user accounts ($event40Count events)"
            Impact = "HIGH - Certificate issued before user account creation"
            Action = "Either reissue certificates or implement CertificateBackdatingCompensation. For temporary workaround (5 years backdating):"
            Command = 'New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "CertificateBackdatingCompensation" -Value 0x9660180 -PropertyType DWORD'
        }
    }

    if ($event41Count -gt 0) {
        $recommendations += @{
            Issue = "SID mismatch between user and certificate ($event41Count events)"
            Impact = "HIGH - Certificate SID extension doesn't match user"
            Action = "Reissue certificates with correct SID extension or create strong manual mapping"
            Command = 'Certificates must be reissued by your Certificate Authority'
        }
    }

    return $recommendations
}

# Validate and set dates
try {
    if ($StartDate -and $EndDate) {
        $start = [datetime]::ParseExact($StartDate, "yyyy-MM-dd", $null)
        $end = [datetime]::ParseExact($EndDate, "yyyy-MM-dd", $null)
    }
    else {
        $end = Get-Date
        $start = $end.AddDays(-([int]$Days))
    }
}
catch {
    Write-Host "Error parsing dates. Use format yyyy-MM-dd" -ForegroundColor Red
    exit 1
}

# Check registry settings
$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
$regValue = if ($TestMode) { 
    1  # Simulated Audit Mode for test
} else {
    (Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
}

$serverInfo = @{
    ServerName = if ($TestMode) { "TEST-DC01" } else { $env:COMPUTERNAME }
    StartTime = $start
    EndTime = $end
    EnforcementMode = switch ($regValue) {
        0 { "Disabled (NOT RECOMMENDED)" }
        1 { "Audit Mode" }
        2 { "Enforcement Mode" }
        default { "Not Configured (Will default to Enforcement in Feb 2025)" }
    }
}

Write-Output-Unless-Quiet "Certificate Authentication Event Analysis $(if ($TestMode) { '(TEST MODE)' })" "Cyan"
Write-Output-Unless-Quiet "========================================"
Write-Output-Unless-Quiet "Server: $($serverInfo.ServerName)"
Write-Output-Unless-Quiet "Current Enforcement Mode: $($serverInfo.EnforcementMode)"
Write-Output-Unless-Quiet "Time Range: $start to $end"
Write-Output-Unless-Quiet "----------------------------------------"

try {
    Write-Output-Unless-Quiet "Fetching events..." -NoNewline
    
    if ($TestMode) {
        $events = Get-TestEvents -StartTime $start -EndTime $end -Count $TestEventCount
        if (-not $Quiet) { Write-Host "Generated $TestEventCount test events!" -ForegroundColor Green }
    }
    else {
        $pastEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = @(2,3)
            StartTime = $start
            EndTime = $end
        } -ErrorAction Stop | 
        Where-Object { $_.Id -in @(39,40,41) }
        
        if (-not $Quiet) { Write-Host "Done!" -ForegroundColor Green }

        $events = @()
        if ($pastEvents) {
            foreach ($event in $pastEvents) {
                $messageLines = $event.Message -split "`r`n"
                $extractValue = {
                    param($lines, $pattern)
                    ($lines | Where-Object { $_ -match $pattern } | Select-Object -First 1) -replace $pattern, '' -replace '^\s+|\s+$',''
                }

                $eventData = [PSCustomObject]@{
                    TimeStamp = $event.TimeCreated
                    EventID = $event.Id
                    EventType = switch ($event.Id) {
                        39 { "No strong certificate mapping found" }
                        40 { "Certificate predates account" }
                        41 { "User SID mismatch with certificate SID" }
                    }
                    User = & $extractValue $messageLines "User: "
                    CertSubject = & $extractValue $messageLines "Certificate Subject: "
                    CertIssuer = & $extractValue $messageLines "Certificate Issuer: "
                    SerialNumber = & $extractValue $messageLines "Certificate Serial Number: "
                    Thumbprint = & $extractValue $messageLines "Certificate Thumbprint: "
                }
                $events += $eventData
            }
        }
    }

    if ($events.Count -gt 0) {
        # Export to CSV
        $csvPath = "$OutputPath.csv"
        $events | Export-Csv -Path $csvPath -NoTypeInformation

        # Generate summary
        $summary = $events | Group-Object EventID | ForEach-Object {
            [PSCustomObject]@{
                EventID = $_.Name
                Description = switch ($_.Name) {
                    39 { "No strong certificate mapping found" }
                    40 { "Certificate predates account" }
                    41 { "User SID mismatch with certificate SID" }
                }
                Count = $_.Count
            }
        }

        if (-not $Quiet) {
            Write-Host "`nEvent Summary:" -ForegroundColor Green
            $summary | Format-Table -AutoSize
        }

        # Get recommendations
        $recommendations = Get-RemediationSteps -Events $events -RegValue $regValue

        # Export to HTML if requested
        if ($HTML) {
            $htmlPath = "$OutputPath.html"
            
            # Create better formatted summary table
            $summaryTable = $summary | ConvertTo-Html -Fragment | ForEach-Object {
                $_ -replace '<table>', '<table class="summary-table">'
            }
            
            # Create better formatted events table
            $eventsTable = $events | Select-Object @{
                Name='Time'; Expression={$_.TimeStamp}
            }, 
            @{
                Name='Event ID'; Expression={$_.EventID}
            },
            @{
                Name='Event Type'; Expression={$_.EventType}
            },
            @{
                Name='Affected User'; Expression={$_.User}
            },
            @{
                Name='Certificate Subject'; Expression={$_.CertSubject}
            },
            @{
                Name='Certificate Issuer'; Expression={$_.CertIssuer}
            },
            @{
                Name='Serial Number'; Expression={$_.SerialNumber}
            },
            @{
                Name='Thumbprint'; Expression={$_.Thumbprint}
            } | ConvertTo-Html -Fragment | ForEach-Object {
                $_ -replace '<table>', '<table class="events-table">'
            }

            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px;
            line-height: 1.6;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px;
            font-size: 14px;
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left; 
        }
        th { 
            background-color: #f2f2f2; 
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .test-mode { 
            color: #ff6b6b; 
            font-weight: bold;
        }
        .high-impact { 
            color: #dc3545; 
            font-weight: bold;
        }
        .medium-impact { 
            color: #ffc107; 
            font-weight: bold;
        }
        .code-block { 
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            font-family: Consolas, Monaco, 'Courier New', monospace;
            margin: 10px 0;
            border: 1px solid #e9ecef;
            white-space: pre-wrap;
        }
        .remediation-box {
            border: 1px solid #dee2e6;
            padding: 20px;
            margin: 15px 0;
            border-radius: 6px;
            background-color: #fff;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .section {
            margin-bottom: 30px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary-table {
            max-width: 800px;
        }
        .events-table {
            font-size: 13px;
        }
    </style>
</head>
<body>
    <h1>Certificate Authentication Event Analysis $(if ($TestMode) { '<span class="test-mode">(TEST MODE)</span>' })</h1>
    
    <div class="section">
        <h2>Server Information</h2>
        <p><strong>Server:</strong> $($serverInfo.ServerName)</p>
        <p><strong>Enforcement Mode:</strong> $($serverInfo.EnforcementMode)</p>
        <p><strong>Time Range:</strong> $start to $end</p>
    </div>
    
    <div class="section">
        <h2>Event Summary</h2>
        $summaryTable
    </div>
    
    <div class="section">
        <h2>Remediation Steps</h2>
        $(foreach ($rec in $recommendations) {
            @"
            <div class='remediation-box'>
                <h3>$($rec.Issue)</h3>
                <p><strong>Impact: </strong><span class='$($rec.Impact.ToLower().Replace(" ", "-"))-impact'>$($rec.Impact)</span></p>
                <p><strong>Recommended Action: </strong>$($rec.Action)</p>
                <div class='code-block'>$($rec.Command)</div>
            </div>
"@
        })
    </div>
    
    <div class="section">
        <h2>Detailed Events</h2>
        $eventsTable
    </div>
</body>
</html>
"@
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            Write-Output-Unless-Quiet "`nHTML report generated: $htmlPath" "Green"
        }

        # Console output for recommendations
        if (-not $Quiet) {
            Write-Host "`nRemediation Steps:" -ForegroundColor Cyan
            foreach ($rec in $recommendations) {
                Write-Host "`nIssue: $($rec.Issue)" -ForegroundColor Yellow
                Write-Host "Impact: $($rec.Impact)" -ForegroundColor $(if ($rec.Impact -like "*HIGH*") { "Red" } else { "Yellow" })
                Write-Host "Action: $($rec.Action)"
                Write-Host "Command:" -NoNewline
                Write-Host "`n$($rec.Command)" -ForegroundColor Gray
            }
        }

        Write-Output-Unless-Quiet "`nReports generated:"
        Write-Output-Unless-Quiet "CSV Report: $csvPath"
        if ($HTML) { Write-Output-Unless-Quiet "HTML Report: $htmlPath" }
    }
    else {
        Write-Output-Unless-Quiet "`nNo certificate authentication issues found in the specified time range." "Green"
    }
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}