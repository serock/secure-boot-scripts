#Requires -RunAsAdministrator

<#
.SYNOPSIS

Save the UEFI Platform Key (PK) certificate to a file in the current location.

.DESCRIPTION

Save the DER-encoded PK certificate as .\PK0.der.

.PARAMETER Bytes

The bytes of a PK EFI Signature List.

.INPUTS

Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable

.INPUTS

System.Byte[]

.OUTPUTS

None

.EXAMPLE

Get-SecureBootUEFI -Name PK | .\Save-PKCert.ps1
Saved the PK cert, HP UEFI Secure Boot 2013 PK Key, to PK0.der
  This PK cert will expire on 2033-08-23
  The signature owner is f5a96b31-dba0-4faa-a42a-7a0c9832768e

This example demonstrates how to use this script on Windows.

.EXAMPLE

efi-readvar -v PK -o PK.esl ; Get-Content -Path ./PK.esl -AsByteStream -Raw | ./Save-PKCert.ps1
Variable PK, length 886
Saved the PK cert, ASUSTeK MotherBoard PK Certificate, to PK0.der
  This PK cert will expire on 2031-12-26
  The signature owner is 3b053091-6c9f-04cc-b1ac-e2a51e3be5f5

This example demonstrates how to use this script on Linux with PowerShell 7.
#>

param (
    [Parameter(Mandatory, Position=0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [byte[]]$Bytes
)

New-Variable -Name EFI_CERT_X509_GUID -Value ([guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072') -Option Constant

function ToUInt32 {
    param (
        [Parameter(Mandatory, Position=0)]
        [ValidateCount(4, 4)]
        [byte[]]$Bytes
    )
    if ([System.BitConverter]::IsLittleEndian) {
        [uint32]$result = [System.BitConverter]::ToUInt32($Bytes, 0)
    } else {
        $tempByteArray = $Bytes + @()
        [Array]::Reverse($tempByteArray)
        [uint32]$result = [System.BitConverter]::ToUInt32($tempByteArray, 0)
    }
    return $result
}
function Get-CommonName {
    param(
        [Parameter(Mandatory, Position=0)]
        [String]$DN
    )
    $dnParts = ($DN -split ',')
    $cnPart = $dnParts[0].Trim()
    if ($cnPart.StartsWith('CN=')) {
        return $cnPart.Substring(3)
    }
    $cnPart = $dnParts[($dnParts.Length - 1)].Trim()
    if ($cnPart.StartsWith('CN=')) {
        return $cnPart.Substring(3)
    }
    throw 'Failed to get Common Name'
}
[byte[]]$signatureDatabase = $Bytes
[byte[]]$efiSignatureList = $signatureDatabase
[guid]$signatureType = [byte[]]$efiSignatureList[0 .. 15]
# SignatureType should be an EFI_CERT_X509_GUID
if ($signatureType -ne $EFI_CERT_X509_GUID) {
    throw "Unsupported signature type: $signatureType"
}
[uint32]$signatureListSize = ToUInt32 -Bytes $efiSignatureList[16 .. 19]
# Signature Database should have one EFI Signature List
if ($signatureDatabase.Length -ne $signatureListSize) {
    throw 'Signature database does not have one and only one EFI signature list'
}
[uint32]$signatureHeaderSize = ToUInt32 -Bytes $efiSignatureList[20 .. 23]
# SignatureHeaderSize should be zero
if ($signatureHeaderSize -ne 0) {
    throw 'Signature header size is not zero'
}
[uint32]$signatureSize = ToUInt32 -Bytes $efiSignatureList[24 .. 27]
# EFI Signature list should have one signature
if ($signatureListSize - $signatureSize -ne 28) {
    throw 'Signature list does not have one and only one signature'
}
[guid]$signatureOwner = [byte[]]$efiSignatureList[28 .. 43]
[byte[]]$signatureData = $efiSignatureList[44 .. ($signatureListSize - 1)]
[string]$filePath = Join-Path -Path "$($PWD.Path)" -ChildPath 'PK0.der'
[System.IO.File]::WriteAllBytes($filePath, $signatureData)
[System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($signatureData)
[string]$subjectName = Get-CommonName -DN $certificate.Subject
[datetime]$expirationTime = $certificate.NotAfter.ToUniversalTime()
[datetime]$now = [System.DateTime]::UtcNow
[timespan]$timeDelta = $expirationTime - $now

[bool]$badCert = $subjectName.Contains('DO NOT SHIP') -or $subjectName.Contains('DO NOT TRUST')
[bool]$certExpired = $expirationTime -lt $now

if ($badCert -or $certExpired) { $styleSubjectName = 'Red' }
else { $styleSubjectName = 'Green' }

Write-Host 'Saved the PK cert, ' -NoNewline
Write-Host $subjectName -NoNewline -ForegroundColor $styleSubjectName
Write-Host ', to PK0.der'

if ($badCert) {
    Write-Host '  This PK cert was issued with an untrusted key' -ForegroundColor Red
    Write-Host '    Go to https://www.kb.cert.org/vuls/id/455367 for more info' -ForegroundColor Red
}

if ($timeDelta.TotalDays -lt 60) { $styleExpiration = 'Red' }
elseif ($timeDelta.TotalDays -lt 120) { $styleExpiration = 'Yellow' }
else { $styleExpiration = 'Green' }

if ($certExpired) {
    Write-Host "  This PK cert expired on $($expirationTime.ToString('yyyy-MM-dd'))" -ForegroundColor Red
} else {
    Write-Host '  This PK cert will expire on ' -NoNewline
    Write-Host $expirationTime.ToString('yyyy-MM-dd') -ForegroundColor $styleExpiration
}
Write-Host "  The signature owner is $signatureOwner"

[bool]$shouldReplaceCert = $bad_cert -or $timeDelta.TotalDays -lt 60

if ($shouldReplaceCert) {
    Write-Host 'Consider replacing this cert with the ' -NoNewline -ForegroundColor DarkRed
    Write-Host 'Windows OEM Devices PK' -NoNewline -ForegroundColor Red
    Write-Host ' cert' -ForegroundColor DarkRed
}
