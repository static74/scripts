<#
.SYNOPSIS
    Analyzes SSL/TLS certificates from websites for troubleshooting purposes.

.DESCRIPTION
    This interactive script connects to a specified website, retrieves the SSL/TLS
    certificate, and displays comprehensive information useful for system administrators
    troubleshooting certificate issues. Output can be displayed in the terminal and
    optionally saved to a file on the user's desktop.

.NOTES
    Author:         Systems Reliability Engineering
    Version:        1.0
    Requires:       PowerShell 5.1+

.EXAMPLE
    .\Get-CertificateInfo.ps1

    Runs the script interactively, prompting for the target URL and output preferences.
#>

#Requires -Version 5.1

# -----------------------------------------------------------------------------
# Function: Get-SSLCertificate
# Purpose:  Retrieves SSL certificate from a remote host
# -----------------------------------------------------------------------------
function Get-SSLCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [Parameter(Mandatory = $false)]
        [int]$Port = 443,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 10
    )

    $certificate = $null
    $chain = $null
    $sslStream = $null
    $tcpClient = $null

    try {
        # Create TCP connection
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($Hostname, $Port)

        if (-not $connectTask.Wait($TimeoutSeconds * 1000)) {
            throw "Connection timed out after $TimeoutSeconds seconds"
        }

        # Create SSL stream
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            { param($sender, $cert, $chain, $errors) return $true }  # Accept all certs for inspection
        )

        # Authenticate as client
        $sslStream.AuthenticateAsClient($Hostname)

        # Get the certificate
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $sslStream.RemoteCertificate
        )

        # Build the certificate chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chainBuilt = $chain.Build($certificate)

        # Return results
        return @{
            Certificate    = $certificate
            Chain          = $chain
            ChainBuilt     = $chainBuilt
            SslProtocol    = $sslStream.SslProtocol
            CipherAlgorithm = $sslStream.CipherAlgorithm
            CipherStrength = $sslStream.CipherStrength
            HashAlgorithm  = $sslStream.HashAlgorithm
            HashStrength   = $sslStream.HashStrength
            KeyExchange    = $sslStream.KeyExchangeAlgorithm
            KeyExchangeStrength = $sslStream.KeyExchangeStrength
        }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
    }
}

# -----------------------------------------------------------------------------
# Function: Get-CertificateSANs
# Purpose:  Extracts Subject Alternative Names from a certificate
# -----------------------------------------------------------------------------
function Get-CertificateSANs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $sans = @()

    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -eq "2.5.29.17") {  # SAN OID
            $sanExtension = $extension.Format($true)
            $sans = $sanExtension -split "`n" | ForEach-Object {
                $_.Trim() -replace "^DNS Name=", "" -replace "^IP Address=", "IP: "
            } | Where-Object { $_ -ne "" }
        }
    }

    return $sans
}

# -----------------------------------------------------------------------------
# Function: Get-CertificateKeyUsage
# Purpose:  Extracts Key Usage and Enhanced Key Usage from a certificate
# -----------------------------------------------------------------------------
function Get-CertificateKeyUsage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $result = @{
        KeyUsage = @()
        EnhancedKeyUsage = @()
    }

    foreach ($extension in $Certificate.Extensions) {
        # Key Usage (2.5.29.15)
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $result.KeyUsage = $extension.KeyUsages.ToString() -split ", "
        }

        # Enhanced Key Usage (2.5.29.37)
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $result.EnhancedKeyUsage = $extension.EnhancedKeyUsages | ForEach-Object {
                "$($_.FriendlyName) ($($_.Value))"
            }
        }
    }

    return $result
}

# -----------------------------------------------------------------------------
# Function: Format-CertificateReport
# Purpose:  Generates a formatted report of certificate information
# -----------------------------------------------------------------------------
function Format-CertificateReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CertData,

        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $true)]
        [int]$TargetPort
    )

    $cert = $CertData.Certificate
    $chain = $CertData.Chain
    $sans = Get-CertificateSANs -Certificate $cert
    $keyUsage = Get-CertificateKeyUsage -Certificate $cert

    # Calculate expiration status
    $now = Get-Date
    $daysUntilExpiry = [math]::Ceiling(($cert.NotAfter - $now).TotalDays)
    $daysSinceIssued = [math]::Floor(($now - $cert.NotBefore).TotalDays)
    $totalValidityDays = [math]::Ceiling(($cert.NotAfter - $cert.NotBefore).TotalDays)

    # Determine expiration status
    if ($cert.NotAfter -lt $now) {
        $expiryStatus = "EXPIRED"
        $expiryColor = "Red"
    }
    elseif ($daysUntilExpiry -le 30) {
        $expiryStatus = "EXPIRING SOON"
        $expiryColor = "Yellow"
    }
    elseif ($daysUntilExpiry -le 90) {
        $expiryStatus = "ATTENTION"
        $expiryColor = "Yellow"
    }
    else {
        $expiryStatus = "VALID"
        $expiryColor = "Green"
    }

    # Build the report as a string builder for file output
    $report = [System.Text.StringBuilder]::new()

    [void]$report.AppendLine("")
    [void]$report.AppendLine("================================================================================")
    [void]$report.AppendLine("  SSL/TLS CERTIFICATE ANALYSIS REPORT")
    [void]$report.AppendLine("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$report.AppendLine("================================================================================")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("  Target: ${TargetHost}:${TargetPort}")
    [void]$report.AppendLine("")

    # Basic Certificate Information
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  CERTIFICATE OVERVIEW")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("  Subject:          $($cert.Subject)")
    [void]$report.AppendLine("  Issuer:           $($cert.Issuer)")
    [void]$report.AppendLine("  Serial Number:    $($cert.SerialNumber)")
    [void]$report.AppendLine("  Thumbprint:       $($cert.Thumbprint)")
    [void]$report.AppendLine("  Version:          V$($cert.Version)")
    [void]$report.AppendLine("")

    # Validity Period
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  VALIDITY PERIOD")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("  Status:           $expiryStatus")
    [void]$report.AppendLine("  Not Before:       $($cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    [void]$report.AppendLine("  Not After:        $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    [void]$report.AppendLine("  Total Validity:   $totalValidityDays days")
    [void]$report.AppendLine("  Days Since Issue: $daysSinceIssued days")

    if ($cert.NotAfter -ge $now) {
        [void]$report.AppendLine("  Days Remaining:   $daysUntilExpiry days")
    }
    else {
        [void]$report.AppendLine("  Expired:          $([math]::Abs($daysUntilExpiry)) days ago")
    }
    [void]$report.AppendLine("")

    # Subject Alternative Names
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  SUBJECT ALTERNATIVE NAMES (SANs)")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")

    if ($sans.Count -gt 0) {
        foreach ($san in $sans) {
            [void]$report.AppendLine("  - $san")
        }
    }
    else {
        [void]$report.AppendLine("  (No SANs found)")
    }
    [void]$report.AppendLine("")

    # Key Information
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  KEY INFORMATION")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("  Public Key Algorithm: $($cert.PublicKey.Oid.FriendlyName)")
    [void]$report.AppendLine("  Key Size:             $($cert.PublicKey.Key.KeySize) bits")
    [void]$report.AppendLine("  Signature Algorithm:  $($cert.SignatureAlgorithm.FriendlyName)")
    [void]$report.AppendLine("")

    # Key Usage
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  KEY USAGE")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")

    if ($keyUsage.KeyUsage.Count -gt 0) {
        [void]$report.AppendLine("  Key Usage:")
        foreach ($ku in $keyUsage.KeyUsage) {
            [void]$report.AppendLine("    - $ku")
        }
    }
    else {
        [void]$report.AppendLine("  Key Usage: (Not specified)")
    }
    [void]$report.AppendLine("")

    if ($keyUsage.EnhancedKeyUsage.Count -gt 0) {
        [void]$report.AppendLine("  Enhanced Key Usage:")
        foreach ($eku in $keyUsage.EnhancedKeyUsage) {
            [void]$report.AppendLine("    - $eku")
        }
    }
    else {
        [void]$report.AppendLine("  Enhanced Key Usage: (Not specified)")
    }
    [void]$report.AppendLine("")

    # TLS Connection Details
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  TLS CONNECTION DETAILS")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("  Protocol Version:     $($CertData.SslProtocol)")
    [void]$report.AppendLine("  Cipher Algorithm:     $($CertData.CipherAlgorithm) ($($CertData.CipherStrength)-bit)")
    [void]$report.AppendLine("  Hash Algorithm:       $($CertData.HashAlgorithm) ($($CertData.HashStrength)-bit)")
    [void]$report.AppendLine("  Key Exchange:         $($CertData.KeyExchange) ($($CertData.KeyExchangeStrength)-bit)")
    [void]$report.AppendLine("")

    # Certificate Chain
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  CERTIFICATE CHAIN")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")

    if ($CertData.ChainBuilt) {
        [void]$report.AppendLine("  Chain Status: VALID")
    }
    else {
        [void]$report.AppendLine("  Chain Status: INVALID - Chain could not be built")
    }
    [void]$report.AppendLine("")

    $chainIndex = 0
    foreach ($element in $chain.ChainElements) {
        $chainCert = $element.Certificate
        $prefix = if ($chainIndex -eq 0) { "[Leaf]" } elseif ($chainIndex -eq $chain.ChainElements.Count - 1) { "[Root]" } else { "[Intermediate]" }

        [void]$report.AppendLine("  $chainIndex. $prefix")
        [void]$report.AppendLine("     Subject:    $($chainCert.Subject)")
        [void]$report.AppendLine("     Issuer:     $($chainCert.Issuer)")
        [void]$report.AppendLine("     Expires:    $($chainCert.NotAfter.ToString('yyyy-MM-dd'))")
        [void]$report.AppendLine("     Thumbprint: $($chainCert.Thumbprint)")
        [void]$report.AppendLine("")

        $chainIndex++
    }

    # Chain Status/Errors
    if ($chain.ChainStatus.Count -gt 0) {
        [void]$report.AppendLine("  Chain Warnings/Errors:")
        foreach ($status in $chain.ChainStatus) {
            if ($status.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError) {
                [void]$report.AppendLine("    - $($status.Status): $($status.StatusInformation)")
            }
        }
        [void]$report.AppendLine("")
    }

    # Troubleshooting Checklist
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  TROUBLESHOOTING CHECKLIST")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")

    # Check hostname match
    $hostnameMatch = $false
    if ($cert.Subject -match "CN=([^,]+)") {
        if ($Matches[1] -eq $TargetHost -or $Matches[1] -eq "*." + ($TargetHost -replace "^[^.]+\.","")) {
            $hostnameMatch = $true
        }
    }
    foreach ($san in $sans) {
        $sanClean = $san -replace "^DNS Name=", ""
        if ($sanClean -eq $TargetHost) {
            $hostnameMatch = $true
        }
        # Check wildcard
        if ($sanClean -match "^\*\.(.+)$") {
            $wildcardDomain = $Matches[1]
            $targetDomain = $TargetHost -replace "^[^.]+\.", ""
            if ($wildcardDomain -eq $targetDomain) {
                $hostnameMatch = $true
            }
        }
    }

    $checkHostname = if ($hostnameMatch) { "[PASS]" } else { "[FAIL]" }
    $checkExpiry = if ($cert.NotAfter -gt $now) { "[PASS]" } else { "[FAIL]" }
    $checkChain = if ($CertData.ChainBuilt) { "[PASS]" } else { "[WARN]" }
    $checkTls = if ($CertData.SslProtocol -match "Tls12|Tls13") { "[PASS]" } else { "[WARN]" }
    $checkKeySize = if ($cert.PublicKey.Key.KeySize -ge 2048) { "[PASS]" } else { "[WARN]" }

    [void]$report.AppendLine("  $checkHostname Hostname matches certificate")
    [void]$report.AppendLine("  $checkExpiry Certificate is not expired")
    [void]$report.AppendLine("  $checkChain Certificate chain is valid")
    [void]$report.AppendLine("  $checkTls TLS 1.2 or higher in use")
    [void]$report.AppendLine("  $checkKeySize Key size is 2048 bits or greater")
    [void]$report.AppendLine("")

    # Common Issues
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("  COMMON ISSUES TO CHECK")
    [void]$report.AppendLine("--------------------------------------------------------------------------------")
    [void]$report.AppendLine("")

    if (-not $hostnameMatch) {
        [void]$report.AppendLine("  [!] HOSTNAME MISMATCH")
        [void]$report.AppendLine("      The target hostname '$TargetHost' does not appear in the certificate's")
        [void]$report.AppendLine("      Subject CN or Subject Alternative Names. This will cause browser warnings.")
        [void]$report.AppendLine("")
    }

    if ($cert.NotAfter -lt $now) {
        [void]$report.AppendLine("  [!] CERTIFICATE EXPIRED")
        [void]$report.AppendLine("      The certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd')).")
        [void]$report.AppendLine("      Renew the certificate immediately.")
        [void]$report.AppendLine("")
    }
    elseif ($daysUntilExpiry -le 30) {
        [void]$report.AppendLine("  [!] CERTIFICATE EXPIRING SOON")
        [void]$report.AppendLine("      The certificate expires in $daysUntilExpiry days ($($cert.NotAfter.ToString('yyyy-MM-dd'))).")
        [void]$report.AppendLine("      Plan for renewal now.")
        [void]$report.AppendLine("")
    }

    if (-not $CertData.ChainBuilt) {
        [void]$report.AppendLine("  [!] CERTIFICATE CHAIN INCOMPLETE")
        [void]$report.AppendLine("      The certificate chain could not be fully validated. This may indicate:")
        [void]$report.AppendLine("      - Missing intermediate certificates on the server")
        [void]$report.AppendLine("      - Self-signed or untrusted root CA")
        [void]$report.AppendLine("      - Revoked certificate in the chain")
        [void]$report.AppendLine("")
    }

    if ($CertData.SslProtocol -match "Ssl|Tls10|Tls11") {
        [void]$report.AppendLine("  [!] OUTDATED TLS VERSION")
        [void]$report.AppendLine("      Connection uses $($CertData.SslProtocol), which is deprecated.")
        [void]$report.AppendLine("      Configure the server to use TLS 1.2 or TLS 1.3.")
        [void]$report.AppendLine("")
    }

    if ($cert.PublicKey.Key.KeySize -lt 2048) {
        [void]$report.AppendLine("  [!] WEAK KEY SIZE")
        [void]$report.AppendLine("      Key size of $($cert.PublicKey.Key.KeySize) bits is below recommended minimum.")
        [void]$report.AppendLine("      Use at least 2048-bit RSA or 256-bit ECDSA keys.")
        [void]$report.AppendLine("")
    }

    if ($cert.SignatureAlgorithm.FriendlyName -match "SHA1|MD5") {
        [void]$report.AppendLine("  [!] WEAK SIGNATURE ALGORITHM")
        [void]$report.AppendLine("      Certificate uses $($cert.SignatureAlgorithm.FriendlyName), which is deprecated.")
        [void]$report.AppendLine("      Reissue with SHA-256 or stronger.")
        [void]$report.AppendLine("")
    }

    [void]$report.AppendLine("================================================================================")
    [void]$report.AppendLine("  END OF REPORT")
    [void]$report.AppendLine("================================================================================")

    return @{
        Report = $report.ToString()
        ExpiryStatus = $expiryStatus
        ExpiryColor = $expiryColor
        HostnameMatch = $hostnameMatch
        ChainValid = $CertData.ChainBuilt
    }
}

# -----------------------------------------------------------------------------
# Function: Write-ColoredReport
# Purpose:  Outputs the report to console with color highlighting
# -----------------------------------------------------------------------------
function Write-ColoredReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Report,

        [Parameter(Mandatory = $true)]
        [hashtable]$ReportMeta
    )

    $lines = $Report -split "`n"

    foreach ($line in $lines) {
        # Color code specific lines
        if ($line -match "^\s*Status:\s+(.+)$") {
            $statusText = $Matches[1].Trim()
            $color = switch -Regex ($statusText) {
                "EXPIRED" { "Red" }
                "EXPIRING SOON|ATTENTION" { "Yellow" }
                "VALID" { "Green" }
                default { "White" }
            }
            Write-Host $line -ForegroundColor $color
        }
        elseif ($line -match "^\s*Chain Status:\s+(.+)$") {
            $color = if ($line -match "VALID") { "Green" } else { "Red" }
            Write-Host $line -ForegroundColor $color
        }
        elseif ($line -match "^\s*\[PASS\]") {
            Write-Host $line -ForegroundColor Green
        }
        elseif ($line -match "^\s*\[FAIL\]") {
            Write-Host $line -ForegroundColor Red
        }
        elseif ($line -match "^\s*\[WARN\]") {
            Write-Host $line -ForegroundColor Yellow
        }
        elseif ($line -match "^\s*\[!\]") {
            Write-Host $line -ForegroundColor Red
        }
        elseif ($line -match "^={10,}|^-{10,}") {
            Write-Host $line -ForegroundColor Cyan
        }
        elseif ($line -match "SSL/TLS CERTIFICATE ANALYSIS|END OF REPORT") {
            Write-Host $line -ForegroundColor Cyan
        }
        else {
            Write-Host $line
        }
    }
}

# -----------------------------------------------------------------------------
# Main Script Execution
# -----------------------------------------------------------------------------

Clear-Host

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  SSL/TLS Certificate Analyzer" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This tool retrieves and analyzes SSL/TLS certificates from websites" -ForegroundColor Gray
Write-Host "to help troubleshoot certificate-related issues." -ForegroundColor Gray
Write-Host ""

# -----------------------------------------------------------------------------
# Gather User Input
# -----------------------------------------------------------------------------

# Get target URL/hostname
do {
    $targetInput = Read-Host -Prompt "Enter the target website (e.g., 'www.example.com' or 'https://example.com:8443')"

    if ([string]::IsNullOrWhiteSpace($targetInput)) {
        Write-Host "ERROR: Please enter a valid website address." -ForegroundColor Yellow
    }
} while ([string]::IsNullOrWhiteSpace($targetInput))

# Parse the input to extract hostname and port
$targetHost = $targetInput
$targetPort = 443

# Remove protocol prefix if present
$targetHost = $targetHost -replace "^https?://", ""

# Extract port if specified
if ($targetHost -match "^(.+):(\d+)(.*)$") {
    $targetHost = $Matches[1]
    $targetPort = [int]$Matches[2]
}

# Remove trailing path if present
$targetHost = $targetHost -replace "/.*$", ""

Write-Host ""
Write-Host "Target: $targetHost`:$targetPort" -ForegroundColor Gray
Write-Host ""

# Ask about output preference
Write-Host "Output Options:" -ForegroundColor White
Write-Host "  1. Display in terminal only" -ForegroundColor Gray
Write-Host "  2. Display in terminal AND save to Desktop" -ForegroundColor Gray
Write-Host ""

do {
    $outputChoice = Read-Host -Prompt "Select output option (1 or 2)"

    if ($outputChoice -notmatch "^[12]$") {
        Write-Host "ERROR: Please enter 1 or 2." -ForegroundColor Yellow
    }
} while ($outputChoice -notmatch "^[12]$")

$saveToFile = ($outputChoice -eq "2")

Write-Host ""
Write-Host "Connecting to $targetHost`:$targetPort..." -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# Retrieve and Analyze Certificate
# -----------------------------------------------------------------------------

try {
    # Get the certificate data
    $certData = Get-SSLCertificate -Hostname $targetHost -Port $targetPort -TimeoutSeconds 15

    if ($null -eq $certData -or $null -eq $certData.Certificate) {
        throw "Failed to retrieve certificate from the server."
    }

    Write-Host "Certificate retrieved successfully." -ForegroundColor Green
    Write-Host ""

    # Generate the report
    $reportResult = Format-CertificateReport -CertData $certData -TargetHost $targetHost -TargetPort $targetPort

    # Display the report with colors
    Write-ColoredReport -Report $reportResult.Report -ReportMeta $reportResult

    # Save to file if requested
    if ($saveToFile) {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $safeHostname = $targetHost -replace "[^a-zA-Z0-9\-\.]", "_"
        $fileName = "CertReport_${safeHostname}_${timestamp}.txt"
        $filePath = Join-Path -Path $desktopPath -ChildPath $fileName

        $reportResult.Report | Out-File -FilePath $filePath -Encoding UTF8

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Report saved to: $filePath" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
    }
}
catch {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  ERROR: Failed to Analyze Certificate" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  - Verify the hostname is correct and accessible" -ForegroundColor White
    Write-Host "  - Check if the server is listening on port $targetPort" -ForegroundColor White
    Write-Host "  - Ensure no firewall is blocking the connection" -ForegroundColor White
    Write-Host "  - Confirm the server has SSL/TLS enabled" -ForegroundColor White
    Write-Host ""

    exit 1
}

Write-Host ""
