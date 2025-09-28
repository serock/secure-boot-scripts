<#
.SYNOPSIS

Select an authenticated variable's EFI Signature List.

.DESCRIPTION

Select an authenticated variable's EFI Signature List as a byte array.

.PARAMETER Bytes

The bytes of authenticated variable.

.INPUTS

System.Byte[]

.OUTPUTS

System.Byte[]

.EXAMPLE

Get-Content -Path ..\..\..\Downloads/KEKUpdate_HP_PK5.bin -Encoding Byte -Raw | .\Select-EFISignatureList.ps1 | Set-Content -Path ..\..\..\Downloads/KEKUpdate_HP_PK5.esl -Encoding Byte

This example demonstrates how to use this script on Windows.

.EXAMPLE

Get-Content -Path ../../../Downloads/KEKUpdate_HP_PK5.bin -AsByteStream -Raw | ./Select-EFISignatureList.ps1 | Set-Content -Path ../../../Downloads/KEKUpdate_HP_PK5.esl -AsByteStream

This example demonstrates how to use this script on Linux with PowerShell 7.
#>

param (
    [Parameter(Mandatory, Position=0, ValueFromPipeline)]
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
[byte[]]$authVar = $Bytes
[uint32]$signedDataLength = ToUInt32 -Bytes $authVar[16 .. 19]
[uint32]$byteIndex = $signedDataLength + 16
[guid]$signatureType = [byte[]]$authVar[$byteIndex .. ($byteIndex + 15)]
if ($signatureType -notin $EFI_CERT_X509_GUID,$EFI_CERT_SHA256_GUID) {
    throw "Unsupported signature type: $signatureType"
}
[uint32]$signatureListSize = ToUInt32 -Bytes $authVar[($byteIndex + 16) .. ($byteIndex + 19)]
[byte[]]$efiSignatureList = $authVar[$byteIndex .. ($byteIndex + $signatureListSize - 1)]
Write-Output -InputObject $efiSignatureList
