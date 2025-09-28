#Requires -RunAsAdministrator

<#
.SYNOPSIS

Save each UEFI authorized signature database (db) certificate and hash list to a separate file in the current location.

.DESCRIPTION

Save each DER-encoded db certificate as .\db{i}.der and each hash list as .\db{i}.hsh, where {i} is 0, 1, 2, ..., etc.

.PARAMETER Bytes

The bytes of a db EFI Signature List.

.INPUTS

Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable

.INPUTS

System.Byte[]

.OUTPUTS

None

.EXAMPLE

Get-SecureBootUEFI -Name db | .\Save-DbCertsAndHashes.ps1
Saved the db cert, Microsoft Windows Production PCA 2011, to db0.der
  This db cert will expire on 2026-10-19
  The signature owner is 77fa9abd-0359-4d32-bd60-28f4e78f784b
Saved the db cert, Microsoft Corporation UEFI CA 2011, to db1.der
  This db cert will expire on 2026-06-27
  The signature owner is 77fa9abd-0359-4d32-bd60-28f4e78f784b

This example demonstrates how to use this script on Windows.

.EXAMPLE

efi-readvar -v db -o db.esl ; Get-Content -Path ./db.esl -AsByteStream -Raw | ./Save-DbCertsAndHashes.ps1
Variable db, length 6322
Saved the db cert, ASUSTeK MotherBoard SW Key Certificate, to db0.der
  This db cert will expire on 2031-12-26
  The signature owner is 3b053091-6c9f-04cc-b1ac-e2a51e3be5f5
Saved the db cert, ASUSTeK Notebook SW Key Certificate, to db1.der
  This db cert will expire on 2031-12-27
  The signature owner is 3b053091-6c9f-04cc-b1ac-e2a51e3be5f5
Saved the db cert, Microsoft Corporation UEFI CA 2011, to db2.der
  This db cert will expire on 2026-06-27
  The signature owner is 77fa9abd-0359-4d32-bd60-28f4e78f784b
Saved the db cert, Microsoft Windows Production PCA 2011, to db3.der
  This db cert will expire on 2026-10-19
  The signature owner is 77fa9abd-0359-4d32-bd60-28f4e78f784b
Saved the db cert, Canonical Ltd. Master Certificate Authority, to db4.der
  This db cert will expire on 2042-04-11
  The signature owner is 6dc40ae4-2ee8-9c4c-a314-0fc7b2008710
Saved the db hash, f58fbdf71be8c37cbbd6944e472c450b1043817b972914487c221033f3079e43, to db5.hsh
  The signature owner is 00000000-0000-0000-0000-000000000000
Saved the db hash, 04970157de52cdae14cf17ee369881d6245b3a6ab6352eabaee588a0584b0303, to db5.hsh
  The signature owner is 00000000-0000-0000-0000-000000000000
Saved the db hash, f16b5fc361183f587120e602c0d65773afdfe786124184fa70805258d76d594c, to db5.hsh
  The signature owner is 00000000-0000-0000-0000-000000000000
Saved the db hash, 7e021f15e3a67b75ace884999bedffe34213792a611e40e562e87e6b9a0cb282, to db5.hsh
  The signature owner is 00000000-0000-0000-0000-000000000000
Saved the db hash, a5d109b2afa3fa90878f70382b2388fcd2feaeae8a51b80add048e9f876b2a4e, to db5.hsh
  The signature owner is 00000000-0000-0000-0000-000000000000

This example demonstrates how to use this script on Linux with PowerShell 7.
#>

param (
    [Parameter(Mandatory, Position=0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [byte[]]$Bytes
)

New-Variable -Name EFI_CERT_SHA256_GUID -Value ([guid]'c1c41626-504c-4092-aca9-41f936934328') -Option Constant
New-Variable -Name EFI_CERT_X509_GUID   -Value ([guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072') -Option Constant

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
        [string]$DN
    )
    [string[]]$dnParts = ($DN -split ',')
    [string]$cnPart = $dnParts[0].Trim()
    if ($cnPart.StartsWith('CN=')) {
        return $cnPart.Substring(3)
    }
    [string]$cnPart = $dnParts[($dnParts.Length - 1)].Trim()
    if ($cnPart.StartsWith('CN=')) {
        return $cnPart.Substring(3)
    }
    throw 'Failed to get Common Name'
}
[byte[]]$signatureDatabase = $Bytes
# Signature Database should have at least one EFI Signature List
if ($signatureDatabase.Length -lt 28) {
    throw 'Signature database does not have at least one EFI Signature List'
}
[int]$dbIndex = 0
[int]$byteIndex = 0
while ($byteIndex -lt $signatureDatabase.Length - 1) {
    if ($byteIndex + 28 -gt $signatureDatabase.Length) {
       throw 'Invalid EFI signature list'
    }
    [guid]$signatureType = [byte[]]$signatureDatabase[$byteIndex .. ($byteIndex + 15)]
    # SignatureType should be an EFI_CERT_X509_GUID
    if ($signatureType -notin $EFI_CERT_X509_GUID,$EFI_CERT_SHA256_GUID) {
        throw "Unsupported signature type: $signatureType"
    }
    [uint32]$signatureListSize = ToUInt32 -Bytes $signatureDatabase[($byteIndex + 16) .. ($byteIndex + 19)]
    # EFI Signature List should fit within Signature Database
    if ($byteIndex + $signatureListSize -gt $signatureDatabase.Length) {
        throw 'Invalid EFI signature list size'
    }
    [uint32]$signatureHeaderSize = ToUInt32 -Bytes $signatureDatabase[($byteIndex + 20) .. ($byteIndex + 23)]
    # SignatureHeaderSize should be zero
    if ($signatureHeaderSize -ne 0) {
        throw 'Signature header size is not zero'
    }
    [uint32]$signatureSize = ToUInt32 -Bytes $signatureDatabase[($byteIndex + 24) .. ($byteIndex + 27)]
    if ($signatureType -eq $EFI_CERT_X509_GUID) {
        # EFI Signature list should have one signature
        if ($signatureListSize - $signatureSize -ne 28) {
            throw 'Signature list does not have one and only one signature'
        }
        [guid]$signatureOwner = [byte[]]$signatureDatabase[($byteIndex + 28) .. ($byteIndex + 43)]
        [byte[]]$signatureData = $signatureDatabase[($byteIndex + 44) .. ($byteIndex + $signatureListSize - 1)]
        [string]$filePath = Join-Path -Path "$($PWD.Path)" -ChildPath "db$dbIndex.der"
        [System.IO.File]::WriteAllBytes($filePath, $signatureData)
    
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($signatureData)
        [string]$subjectName = Get-CommonName -DN $certificate.Subject

        [datetime]$expirationTime = $certificate.NotAfter.ToUniversalTime()
        [datetime]$now = [System.DateTime]::UtcNow
        [timespan]$timeDelta = $expirationTime - $now
        [bool]$certExpired = $expirationTime -lt $now

        if ($certExpired) { [string]$styleSubjectName = 'Red' }
        else { [string]$styleSubjectName = 'Green' }

        Write-Host 'Saved the db cert, ' -NoNewline
        Write-Host $subjectName -NoNewline -ForegroundColor $styleSubjectName
        Write-Host ", to db$dbIndex.der"

        if ($timeDelta.TotalDays -lt 60) { $styleExpiration = 'Red' }
        elseif ($timeDelta.TotalDays -lt 120) { $styleExpiration = 'Yellow' }
        else { $styleExpiration = 'Green' }

        if ($certExpired) {
            Write-Host "  This db cert expired on $($expirationTime.ToString('yyyy-MM-dd'))" -ForegroundColor Red
        } else {
            Write-Host '  This db cert will expire on ' -NoNewline
            Write-Host $expirationTime.ToString('yyyy-MM-dd') -ForegroundColor $styleExpiration
        }
        Write-Host "  The signature owner is $signatureOwner"
    } else {
        if ($signatureSize -ne 48) {
            throw 'Invalid signature size'
        }
        [uint32]$signatureDataSize = $signatureListSize - 28
        if ($signatureDataSize % $signatureSize -ne 0) {
            throw 'Invalid signature list size'
        }
        [uint32]$signatureCount = $signatureDataSize / $signatureSize
        [byte[]]$hashBytes = [byte[]]::new(32 * $signatureCount)
        [int]$hashIndex = 0
        [int]$hashByteIndex = 0
        [string]$filePath = Join-Path -Path "$($PWD.Path)" -ChildPath "db$dbIndex.hsh"
        while ($hashIndex -lt $signatureCount) {
            [System.Array]::Copy($signatureDatabase, ($byteIndex + 28 + $hashIndex * 48 + 16), $hashBytes, $hashByteIndex, 32)
            [string]$dbHash = [System.BitConverter]::ToString($signatureDatabase[($byteIndex + 28 + $hashIndex * 48 + 16) .. ($byteIndex + 28 + $hashIndex * 48 + 47)]).ToLower() -replace '-' 
            Write-Host "Saved the db hash, $dbHash, to db$dbIndex.hsh"
            [guid]$signatureOwner = [byte[]]$signatureDatabase[($byteIndex + 28 + $hashIndex * 48) .. ($byteIndex + 28 + $hashIndex * 48 + 15)]
            Write-Host "  The signature owner is $signatureOwner"
            $hashIndex++
            $hashByteIndex += 32
        }
        [System.IO.File]::WriteAllBytes($filePath, $hashBytes)
    }
    $dbIndex++
    $byteIndex += $signatureListSize
}
