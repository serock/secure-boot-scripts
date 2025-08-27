New-Variable -Name EFI_CERT_X509_GUID -Value ([Guid] "a5c059a1-94e4-4aa7-87b5-ab155c2bf072") -Option Constant
New-Variable -Name MICROSOFT_KEK_2023_CERT_NAME -Value "Microsoft Corporation KEK 2K CA 2023" -Option Constant

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
$signatureDatabase = (Get-SecureBootUEFI -Name KEK).Bytes
# Signature Database should have at least one EFI Signature List
if ($signatureDatabase.Length -lt 28) {
    throw "Signature database does not have at least one EFI Signature List"
}
$noMicrosoftKek2023Cert = $true
$kekIndex = 0
$byteIndex = 0
while ($byteIndex -lt $signatureDatabase.Length - 1) {
    if ($byteIndex + 28 -gt $signatureDatabase.Length) {
       throw "Invalid EFI signature list"
    }
    $signatureType = [Guid] [Byte[]] $signatureDatabase[$byteIndex .. ($byteIndex + 15)]
    # SignatureType should be an EFI_CERT_X509_GUID
    if ($signatureType -ne $EFI_CERT_X509_GUID) {
        throw "Unsupported signature type: $signatureType"
    }
    $signatureListSize = ToUInt32 -ByteArray ([Byte[]] $signatureDatabase[($byteIndex + 16) .. ($byteIndex + 19)])
    # Signature Database should have at least one EFI Signature List
    if ($byteIndex + $signatureListSize -gt $signatureDatabase.Length) {
        throw "Invalid EFI signature list size"
    }
    $signatureHeaderSize = ToUInt32 -ByteArray ([Byte[]] $signatureDatabase[($byteIndex + 20) .. ($byteIndex + 23)])
    # SignatureHeaderSize should be zero
    if ($signatureHeaderSize -ne 0) {
        throw "Signature header size is not zero"
    }
    $signatureSize = ToUInt32 -ByteArray ([Byte[]] $signatureDatabase[($byteIndex + 24) .. ($byteIndex + 27)])
    # EFI Signature list should have one signature
    if ($signatureListSize - $signatureSize -ne 28) {
        throw "Signature list does not have one and only one signature"
    }
    $signatureOwner = [Guid] [Byte[]] $signatureDatabase[($byteIndex + 28) .. ($byteIndex + 43)]
    $signatureData = [Byte[]] $signatureDatabase[($byteIndex + 44) .. ($byteIndex + $signatureListSize - 1)]
    $filePath = $PWD.Path + ".\KEK" + $kekIndex + ".cer"
    [System.IO.File]::WriteAllBytes($filePath, $signatureData)
    
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($signatureData)
    $subjectName = Get-CommonName -DN $certificate.Subject
    if ($subjectName -eq $MICROSOFT_KEK_2023_CERT_NAME) {
        $noMicrosoftKek2023Cert = $false
    }

    $expirationTime = $certificate.NotAfter.ToUniversalTime()
    $now = [System.DateTime]::UtcNow
    $timeDelta = $expirationTime - $now
    $certExpired = $expirationTime -lt $now

    if ($certExpired) { $styleSubjectName = "Red" }
    else { $styleSubjectName = "Green" }

    Write-Host "Saved the KEK cert, " -NoNewline
    Write-Host $subjectName -NoNewline -ForegroundColor $styleSubjectName
    Write-Host (", to KEK" + $kekIndex + ".cer")

    if ($timeDelta.TotalDays -lt 60) { $styleExpiration = "Red" }
    elseif ($timeDelta.TotalDays -lt 120) { $styleExpiration = "Yellow" }
    else { $styleExpiration = "Green" }

    if ($certExpired) {
        Write-Host ("  This KEK cert expired on " + $expirationTime.ToString("yyyy-MM-dd")) -NoNewline -ForegroundColor Red
    } else {
        Write-Host "  This KEK cert will expire on " -NoNewline
        Write-Host $expirationTime.ToString("yyyy-MM-dd") -ForegroundColor $styleExpiration
    }
    Write-Host ("  The signature owner is " + $signatureOwner)

    $kekIndex += 1
    $byteIndex += $signatureListSize
}

if ($noMicrosoftKek2023Cert) {
    Write-Host "Consider adding the " -NoNewline -ForegroundColor DarkRed
    Write-Host $MICROSOFT_KEK_2023_CERT_NAME  -NoNewline -ForegroundColor Red
    Write-Host " cert." -ForegroundColor DarkRed
}
