# KB5014754 Certificate Authentication Event Analysis

This script analyzes certificate authentication events related to KB5014754 and generates detailed reports to help identify and remediate potential issues.

## Overview

The script checks for certificate authentication events (Event IDs 39, 40, 41) and provides:
- CSV report with detailed event information
- Optional HTML report with interactive formatting
- Remediation steps and recommendations
- Registry configuration status

## Event Types

| Event ID | Description | Impact |
|----------|-------------|---------|
| 39 | No strong certificate mapping found | HIGH - Certificates using weak mapping methods |
| 40 | Certificate predates user account | HIGH - Certificate issued before user account creation |
| 41 | User SID mismatch with certificate SID | HIGH - Certificate SID extension doesn't match user |

## Usage

Basic usage examples:

```powershell
# Check last 24 hours with HTML report
.\Check-Certificate-Events.ps1 -HTML

# Check specific date range
.\Check-Certificate-Events.ps1 -StartDate "2024-01-01" -EndDate "2024-01-31"

# Check last 7 days with custom output path
.\Check-Certificate-Events.ps1 -Days 7 -OutputPath "C:\Reports\CertAudit"

# Run in test mode
.\Check-Certificate-Events.ps1 -TestMode -TestEventCount 20 -HTML
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Days | 1 | Number of days to look back for events |
| StartDate | - | Start date (format: yyyy-MM-dd) |
| EndDate | - | End date (format: yyyy-MM-dd) |
| OutputPath | .\CertEvents_[timestamp] | Report save location |
| HTML | False | Generate HTML report |
| Quiet | False | Suppress console output |
| TestMode | False | Run with sample data |
| TestEventCount | 10 | Number of test events |

## Registry Settings

The script checks StrongCertificateBindingEnforcement status:

| Value | Mode | Description |
|-------|------|-------------|
| 0 | Disabled | Security enhancements disabled (Not Recommended) |
| 1 | Audit | Test mode - logs issues but allows authentication |
| 2 | Enforcement | Full security enforcement |
| Not Set | Default | Will default to Enforcement in February 2025 |