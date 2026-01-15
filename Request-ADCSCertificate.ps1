<#
.SYNOPSIS
    Requests a certificate from an Active Directory Certificate Services (AD CS) Enterprise CA.

.DESCRIPTION
    This interactive script prompts the administrator for certificate details and submits
    an enrollment request to the internal Enterprise CA using the Get-Certificate cmdlet.

.NOTES
    Author:         Systems Reliability Engineering
    Version:        1.0
    Requires:       PowerShell 5.1+, Windows Server with AD CS Client components

    ============================================================================
    PREREQUISITE - IMPORTANT AD CS TEMPLATE CONFIGURATION
    ============================================================================

    For this script to function correctly, the AD CS Certificate Template MUST be
    configured with the following setting:

    1. Open the Certificate Templates MMC snap-in (certtmpl.msc)
    2. Right-click the template you intend to use -> Properties
    3. Navigate to the "Subject Name" tab
    4. Select: "Supply in the request"

    If the template is configured to "Build from Active Directory information,"
    the manually supplied Common Name (CN) and Subject Alternative Name (SAN)
    inputs will be IGNORED by the CA, or the enrollment will fail with an error.

    Additionally, ensure:
    - The requesting user/computer has "Enroll" permission on the template
    - The template is published to an Enterprise CA
    - Network connectivity to the CA is available (RPC/DCOM)
    ============================================================================

.EXAMPLE
    .\Request-ADCSCertificate.ps1

    Runs the script interactively, prompting for all required values.
#>

#Requires -Version 5.1

# -----------------------------------------------------------------------------
# Function: Get-ValidatedInput
# Purpose:  Prompts user for input and validates it is not empty/whitespace
# -----------------------------------------------------------------------------
function Get-ValidatedInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptMessage,

        [Parameter(Mandatory = $false)]
        [string]$ExampleValue = "",

        [Parameter(Mandatory = $false)]
        [switch]$Required
    )

    $inputValue = $null

    do {
        # Build the prompt string with example if provided
        if ($ExampleValue) {
            $fullPrompt = "$PromptMessage (e.g., '$ExampleValue')"
        }
        else {
            $fullPrompt = $PromptMessage
        }

        $inputValue = Read-Host -Prompt $fullPrompt

        # Check if input is empty and field is required
        if ($Required -and [string]::IsNullOrWhiteSpace($inputValue)) {
            Write-Host "ERROR: This field is required. Please enter a value." -ForegroundColor Yellow
        }

    } while ($Required -and [string]::IsNullOrWhiteSpace($inputValue))

    return $inputValue.Trim()
}

# -----------------------------------------------------------------------------
# Main Script Execution
# -----------------------------------------------------------------------------

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  AD CS Certificate Request Tool" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will request a certificate from your Enterprise CA." -ForegroundColor Gray
Write-Host "Please ensure you have the necessary permissions on the template." -ForegroundColor Gray
Write-Host ""

# -----------------------------------------------------------------------------
# Gather User Input with Validation
# -----------------------------------------------------------------------------

# Template Name - REQUIRED (will re-prompt if blank)
$TemplateName = Get-ValidatedInput `
    -PromptMessage "Enter the Certificate Template Name" `
    -ExampleValue "InternalWebServer" `
    -Required

# Subject Common Name - REQUIRED
$SubjectCN = Get-ValidatedInput `
    -PromptMessage "Enter the Subject Name (CN)" `
    -ExampleValue "webapp.corp.local" `
    -Required

# DNS Subject Alternative Name - REQUIRED
$DnsName = Get-ValidatedInput `
    -PromptMessage "Enter the DNS Subject Alternative Name (SAN)" `
    -ExampleValue "webapp.corp.local" `
    -Required

# -----------------------------------------------------------------------------
# Display Summary Before Submission
# -----------------------------------------------------------------------------

Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  Certificate Request Summary" -ForegroundColor White
Write-Host "----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  Template:    $TemplateName" -ForegroundColor White
Write-Host "  Subject CN:  CN=$SubjectCN" -ForegroundColor White
Write-Host "  DNS SAN:     $DnsName" -ForegroundColor White
Write-Host "  Store:       Cert:\LocalMachine\My" -ForegroundColor White
Write-Host "----------------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

# Confirm before proceeding
$confirmation = Read-Host -Prompt "Proceed with certificate request? (Y/N)"
if ($confirmation -notmatch '^[Yy]') {
    Write-Host "Certificate request cancelled by user." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Submitting certificate request to Enterprise CA..." -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# Submit Certificate Request with Error Handling
# -----------------------------------------------------------------------------

try {
    # Build the subject name in X.500 format
    $Subject = "CN=$SubjectCN"

    # Request the certificate using Get-Certificate
    # -Template: Specifies the AD CS certificate template
    # -SubjectName: The X.500 distinguished name for the subject
    # -DnsName: Adds DNS entries to the Subject Alternative Name extension
    # -CertStoreLocation: Target store for the issued certificate
    $certificateRequest = Get-Certificate `
        -Template $TemplateName `
        -SubjectName $Subject `
        -DnsName $DnsName `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -ErrorAction Stop

    # Check the status of the request
    if ($certificateRequest.Status -eq "Issued") {
        # Success - Certificate was issued immediately
        $newCert = $certificateRequest.Certificate

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  SUCCESS: Certificate Issued" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Thumbprint:   $($newCert.Thumbprint)" -ForegroundColor Green
        Write-Host "  Subject:      $($newCert.Subject)" -ForegroundColor Green
        Write-Host "  Issuer:       $($newCert.Issuer)" -ForegroundColor Green
        Write-Host "  Valid From:   $($newCert.NotBefore)" -ForegroundColor Green
        Write-Host "  Valid Until:  $($newCert.NotAfter)" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Store Path:   Cert:\LocalMachine\My\$($newCert.Thumbprint)" -ForegroundColor Green
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
    }
    elseif ($certificateRequest.Status -eq "Pending") {
        # Certificate is pending CA manager approval
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host "  PENDING: Certificate Awaiting Approval" -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  The certificate request has been submitted but requires" -ForegroundColor Yellow
        Write-Host "  approval from a CA manager before it can be issued." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Request ID: $($certificateRequest.Request.RequestId)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Contact your CA administrator to approve the request." -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Yellow
    }
    else {
        # Unexpected status
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host "  WARNING: Unexpected Request Status" -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Status: $($certificateRequest.Status)" -ForegroundColor Yellow
        Write-Host ""
    }
}
catch {
    # -----------------------------------------------------------------------------
    # Error Handling - Provide meaningful troubleshooting guidance
    # -----------------------------------------------------------------------------

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  ERROR: Certificate Enrollment Failed" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Error Message:" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "----------------------------------------------------------------" -ForegroundColor Red
    Write-Host "  Troubleshooting Steps:" -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------" -ForegroundColor Red
    Write-Host ""

    # Analyze the error and provide specific guidance
    $errorMessage = $_.Exception.Message.ToLower()

    if ($errorMessage -match "permission|denied|access") {
        Write-Host "  [Permission Issue Detected]" -ForegroundColor Yellow
        Write-Host "  - Verify you have 'Enroll' permission on the template" -ForegroundColor White
        Write-Host "  - Run this script as Administrator" -ForegroundColor White
        Write-Host "  - Check if your account is in the correct security group" -ForegroundColor White
    }
    elseif ($errorMessage -match "rpc|unavailable|network|connect") {
        Write-Host "  [Connectivity Issue Detected]" -ForegroundColor Yellow
        Write-Host "  - Verify network connectivity to the CA server" -ForegroundColor White
        Write-Host "  - Check if the CA service is running" -ForegroundColor White
        Write-Host "  - Ensure RPC/DCOM ports are not blocked by firewall" -ForegroundColor White
        Write-Host "  - Verify DNS resolution for the CA server" -ForegroundColor White
    }
    elseif ($errorMessage -match "template|not found|invalid") {
        Write-Host "  [Template Issue Detected]" -ForegroundColor Yellow
        Write-Host "  - Verify the template name is spelled correctly" -ForegroundColor White
        Write-Host "  - Ensure the template is published to an Enterprise CA" -ForegroundColor White
        Write-Host "  - Check if the template is enabled and not superseded" -ForegroundColor White
    }
    elseif ($errorMessage -match "subject|name|san|alternative") {
        Write-Host "  [Subject Name Issue Detected]" -ForegroundColor Yellow
        Write-Host "  - Verify the template's 'Subject Name' tab is set to" -ForegroundColor White
        Write-Host "    'Supply in the request' (NOT 'Build from AD info')" -ForegroundColor White
        Write-Host "  - Check that the SAN extension is enabled on the template" -ForegroundColor White
    }
    else {
        Write-Host "  [General Troubleshooting]" -ForegroundColor Yellow
        Write-Host "  - Verify the template name: '$TemplateName'" -ForegroundColor White
        Write-Host "  - Ensure you are running as Administrator" -ForegroundColor White
        Write-Host "  - Check CA server availability and permissions" -ForegroundColor White
        Write-Host "  - Verify template 'Subject Name' is set to 'Supply in request'" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "----------------------------------------------------------------" -ForegroundColor Red
    Write-Host "  Full Error Details (for advanced troubleshooting):" -ForegroundColor Gray
    Write-Host "----------------------------------------------------------------" -ForegroundColor Red
    Write-Host "  Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Gray
    Write-Host ""

    # Exit with error code
    exit 1
}
