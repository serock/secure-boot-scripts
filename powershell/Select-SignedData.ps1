<#
.SYNOPSIS

Select an authenticated variable's signed data.

.DESCRIPTION

Select an authenticated variable's signed data as a byte array.

.PARAMETER Bytes

The bytes of authenticated variable.

.INPUTS

System.Byte[]

.OUTPUTS

System.Byte[]

.EXAMPLE

Get-Content -Path ..\..\..\Downloads/KEKUpdate_HP_PK5.bin -Encoding Byte -Raw | .\Select-SignedData.ps1 | Set-Content -Path ..\..\..\Downloads/KEKUpdate_HP_PK5.p7 -Encoding Byte

This example demonstrates how to use this script on Windows.

.EXAMPLE

Get-Content -Path ../../../Downloads/KEKUpdate_HP_PK5.bin -AsByteStream -Raw | ./Select-SignedData.ps1 | Set-Content -Path ../../../Downloads/KEKUpdate_HP_PK5.p7 -AsByteStream

This example demonstrates how to use this script on Linux with PowerShell 7.
#>

param (
    [Parameter(Mandatory, Position=0, ValueFromPipeline)]
    [byte[]]$Bytes
)

New-Variable -Name EFI_CERT_TYPE_PKCS7_GUID -Value ([guid]'4aafd29d-68df-49ee-8aa9-347d375665a7') -Option Constant

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
function ToUInt16 {
    param (
        [Parameter(Mandatory, Position=0)]
        [ValidateCount(2, 2)]
        [byte[]]$Bytes
    )
    if ([System.BitConverter]::IsLittleEndian) {
        $result = [System.BitConverter]::ToUInt16($Bytes, 0)
    } else {
        $tempByteArray = $Bytes + @()
        [array]::Reverse($tempByteArray)
        $result = [System.BitConverter]::ToUInt16($tempByteArray, 0)
    }
    return $result
}
[byte[]]$authVar = $Bytes
[uint32]$length = ToUInt32 -Bytes $authVar[16 .. 19]
[uint16]$revision = ToUInt16 -Bytes $authVar[20 .. 21]
if ($revision -ne 0x0200) {
    throw "Unexpected revision: $revision"
}
[uint16]$certificateType = ToUInt16 -Bytes $authVar[22 .. 23]
if ($certificateType -ne 0x0ef1) {
    throw "Unexpected certificate type: $certificateType"
}
[guid]$certTypeGuid = [byte[]]$authVar[24 .. 39]
if ($certTypeGuid -ne $EFI_CERT_TYPE_PKCS7_GUID) {
    throw "Unsupported signature type: $certTypeGuid"
}
[byte[]]$signedData = $authVar[40 .. ($length + 15)]
Write-Output -InputObject $signedData
