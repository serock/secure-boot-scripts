New-Variable -Name EFI_CERT_X509_GUID -Value ([Guid] "a5c059a1-94e4-4aa7-87b5-ab155c2bf072") -Option Constant
function ToUInt32 {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateCount(4, 4)]
        [Byte[]]$ByteArray
    )
    if ([System.BitConverter]::IsLittleEndian) {
        $result = [System.BitConverter]::ToUInt32([Byte[]] $ByteArray[0 .. 3], 0)
    } else {
        $tempByteArray = [Byte[]] $ByteArray[0 .. 3]
        [Array]::Reverse($tempByteArray)
        $result = [System.BitConverter]::ToUInt32($tempByteArray, 0)
    }
    return $result
}
function Get-CommonName {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [String]$DN
    )
    $dnParts = ($DN -split ",")
    $cnPart = $dnParts[0].Trim()
    if ($cnPart.StartsWith("CN=")) {
        return $cnPart.Substring(3)
    }
    $cnPart = $dnParts[($dnParts.Length - 1)].Trim()
    if ($cnPart.StartsWith("CN=")) {
        return $cnPart.Substring(3)
    }
    throw "Failed to get Common Name"
}
$signatureDatabase = (Get-SecureBootUEFI -Name PK).Bytes
$efiSignatureList = $signatureDatabase
$signatureType = [Guid] [Byte[]] $efiSignatureList[0 .. 15]
# SignatureType should be an EFI_CERT_X509_GUID
if ($signatureType -ne $EFI_CERT_X509_GUID) {
    throw "Unsupported signature type: $signatureType"
}
$signatureListSize = ToUInt32 -ByteArray ([Byte[]] $efiSignatureList[16 .. 19])
# Signature Database should have one EFI Signature List
if ($signatureDatabase.Length -ne $signatureListSize) {
    throw "Signature database does not have one and only one EFI signature list"
}
$signatureHeaderSize = ToUInt32 -ByteArray ([Byte[]] $efiSignatureList[20 .. 23])
# SignatureHeaderSize should be zero
if ($signatureHeaderSize -ne 0) {
    throw "Signature header size is not zero"
}
$signatureSize = ToUInt32 -ByteArray ([Byte[]] $efiSignatureList[24 .. 27])
# EFI Signature list should have one signature
if ($signatureListSize - $signatureSize -ne 28) {
    throw "Signature list does not have one and only one signature"
}
$signatureOwner = [Guid] [Byte[]] $efiSignatureList[28 .. 43]
$signatureData = [Byte[]] $efiSignatureList[44 .. ($signatureListSize - 1)]
$filePath = $PWD.Path + ".\PK.cer"
[System.IO.File]::WriteAllBytes($filePath, $signatureData)
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($signatureData)
$subjectName = Get-CommonName -DN $certificate.Subject
$expirationTime = $certificate.NotAfter.ToUniversalTime()
$now = [System.DateTime]::UtcNow
$timeDelta = $expirationTime - $now

$badCert = $subjectName.Contains("DO NOT SHIP") -or $subjectName.Contains("DO NOT TRUST")
$certExpired = $expirationTime -lt $now

if ($badCert -or $certExpired) { $styleSubjectName = "Red" }
else { $styleSubjectName = "Green" }

Write-Host "Saved the PK cert, " -NoNewline
Write-Host $subjectName -NoNewline -ForegroundColor $styleSubjectName
Write-Host ", to PK.cer"

if ($badCert) {
    Write-Host "This PK cert was issued with an untrusted key" -ForegroundColor Red
    Write-Host "  Go to https://www.kb.cert.org/vuls/id/455367 for more info." -ForegroundColor Red
}

if ($timeDelta.TotalDays -lt 60) { $styleExpiration = "Red" }
elseif ($timeDelta.TotalDays -lt 120) { $styleExpiration = "Yellow" }
else { $styleExpiration = "Green" }

if ($certExpired) {
    Write-Host "  This PK cert expired on " -NoNewline -ForegroundColor Red
    Write-Host $expirationTime.ToString("yyyy-MM-dd") -NoNewline -ForegroundColor Red
    Write-Host "." -ForegroundColor Red
} else {
    Write-Host "  This PK cert will expire on " -NoNewline
    Write-Host $expirationTime.ToString("yyyy-MM-dd") -NoNewline -ForegroundColor $styleExpiration
    Write-Host "."
}

$shouldReplaceCert = $bad_cert -or $timeDelta.TotalDays -lt 60

if ($shouldReplaceCert) {
    Write-Host "Consider replacing this cert with the " -NoNewline -ForegroundColor DarkRed
    Write-Host "Windows OEM Devices PK" -NoNewline -ForegroundColor Red
    Write-Host " cert." -ForegroundColor DarkRed
}
