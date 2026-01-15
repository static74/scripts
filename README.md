# AD CS Certificate Request Tool

A robust, interactive PowerShell script for requesting certificates from an Active Directory Certificate Services (AD CS) Enterprise CA.

## Overview

This script provides an administrator-friendly interface for submitting certificate enrollment requests to an internal Enterprise CA. It uses the modern `Get-Certificate` cmdlet and includes comprehensive error handling with troubleshooting guidance.

## Requirements

### System Requirements

- Windows Server 2012 R2 or later (or Windows 10/11 with RSAT)
- PowerShell 5.1 or later
- AD CS Client components installed
- Network connectivity to the Enterprise CA

### Permissions Required

- Local Administrator rights on the machine running the script
- **Enroll** permission on the target certificate template
- The computer account (for machine certificates) or user account must be authorized to request certificates

## Prerequisites

### Critical Template Configuration

The AD CS certificate template **must** be configured to accept subject information from the request:

1. Open the Certificate Templates MMC snap-in:
   ```
   certtmpl.msc
   ```

2. Right-click the target template and select **Properties**

3. Navigate to the **Subject Name** tab

4. Select: **Supply in the request**

> **Warning:** If the template is set to "Build from Active Directory information," the manually supplied Common Name (CN) and Subject Alternative Name (SAN) will be **ignored** or cause enrollment to fail.

### Template Publishing

Ensure the certificate template is published to at least one Enterprise CA:

1. Open the Certification Authority MMC snap-in:
   ```
   certsrv.msc
   ```

2. Expand your CA, right-click **Certificate Templates**

3. Select **New** > **Certificate Template to Issue**

4. Select your template and click **OK**

## Usage

### Running the Script

1. Open PowerShell as **Administrator**

2. Navigate to the script directory:
   ```powershell
   cd "C:\Path\To\Scripts"
   ```

3. Execute the script:
   ```powershell
   .\Request-ADCSCertificate.ps1
   ```

### Interactive Prompts

The script will prompt for the following information:

| Prompt | Description | Example |
|--------|-------------|---------|
| **Template Name** | The common name of the AD CS template | `InternalWebServer` |
| **Subject Name (CN)** | The Common Name for the certificate subject | `webapp.corp.local` |
| **DNS SAN** | DNS name for the Subject Alternative Name extension | `webapp.corp.local` |

### Example Session

```
================================================================
  AD CS Certificate Request Tool
================================================================

This script will request a certificate from your Enterprise CA.
Please ensure you have the necessary permissions on the template.

Enter the Certificate Template Name (e.g., 'InternalWebServer'): InternalWebServer
Enter the Subject Name (CN) (e.g., 'webapp.corp.local'): webapp.corp.local
Enter the DNS Subject Alternative Name (SAN) (e.g., 'webapp.corp.local'): webapp.corp.local

----------------------------------------------------------------
  Certificate Request Summary
----------------------------------------------------------------
  Template:    InternalWebServer
  Subject CN:  CN=webapp.corp.local
  DNS SAN:     webapp.corp.local
  Store:       Cert:\LocalMachine\My
----------------------------------------------------------------

Proceed with certificate request? (Y/N): Y

Submitting certificate request to Enterprise CA...

================================================================
  SUCCESS: Certificate Issued
================================================================

  Thumbprint:   A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0
  Subject:      CN=webapp.corp.local
  Issuer:       CN=Corp-Issuing-CA, DC=corp, DC=local
  Valid From:   1/15/2026 8:00:00 AM
  Valid Until:  1/15/2027 8:00:00 AM

  Store Path:   Cert:\LocalMachine\My\A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0

================================================================
```

## Output States

### Success (Green)

Certificate was issued immediately and installed in the local machine store. The output displays:
- Certificate thumbprint
- Subject and issuer information
- Validity period
- Full certificate store path

### Pending (Yellow)

Certificate request was submitted but requires CA manager approval. Contact your PKI administrator to approve the request in the CA console.

### Error (Red)

Enrollment failed. The script provides context-aware troubleshooting guidance based on the error type:
- Permission issues
- Network/connectivity problems
- Template configuration errors
- Subject name conflicts

## Troubleshooting

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| Permission denied | Insufficient enrollment rights | Add user/computer to template security with Enroll permission |
| RPC server unavailable | CA not reachable | Check network connectivity, firewall rules, CA service status |
| Template not found | Typo or unpublished template | Verify template name spelling, ensure it's published to a CA |
| Subject name invalid | Template misconfigured | Set template to "Supply in the request" on Subject Name tab |

### Verifying the Certificate

After successful enrollment, verify the certificate:

```powershell
# List certificates in the local machine store
Get-ChildItem -Path Cert:\LocalMachine\My | Format-Table Subject, Thumbprint, NotAfter

# View specific certificate details
Get-ChildItem -Path Cert:\LocalMachine\My\<thumbprint> | Format-List *
```

### Checking Template Permissions

```powershell
# View effective permissions on a template (requires AD PowerShell module)
Get-ADObject -Filter {objectClass -eq 'pKICertificateTemplate' -and cn -eq 'InternalWebServer'} `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" `
    -Properties nTSecurityDescriptor |
    Select-Object -ExpandProperty nTSecurityDescriptor |
    Select-Object -ExpandProperty Access
```

## Security Considerations

- Run the script with the minimum required privileges
- Audit certificate requests through CA logs
- Implement approval workflows for sensitive certificate templates
- Regularly review template permissions and enrollment activity

## License

Internal use only. Modify and distribute according to your organization's policies.
