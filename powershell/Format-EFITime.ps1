<#
.SYNOPSIS

Format an authenticated variable's EFI time.

.DESCRIPTION

Format an authenticated variable's EFI time as ISO 8601 format (yyyy-MM-ddTHH:mm:ssZ).

.PARAMETER Bytes

The bytes of authenticated variable.

.INPUTS

System.Byte[]

.OUTPUTS

System.String

.EXAMPLE

Get-Content -Path ..\..\..\Downloads\KEKUpdate_HP_PK5.bin -Encoding Byte -Raw | .\Format-EFITime
2010-03-06T19:17:21Z

This example demonstrates how to use this script on Windows.

.EXAMPLE

Get-Content -Path ../../../Downloads/KEKUpdate_HP_PK5.bin -AsByteStream -Raw | ./Format-EFITime
2010-03-06T19:17:21Z

This example demonstrates how to use this script on Linux with PowerShell 7.
#>

param (
    [Parameter(Mandatory, Position=0, ValueFromPipeline)]
    [byte[]]$Bytes
)

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
function ToEfiTime {
    param (
        [Parameter(Mandatory, Position=0)]
        [ValidateCount(16, 16)]
        [byte[]]$Bytes
    )
    return (Get-Date -Year (ToUInt16 -Bytes $Bytes[0 .. 1]) -Month $Bytes[2] -Day $Bytes[3] -Hour $Bytes[4] -Minute $Bytes[5] -Second $Bytes[6] -Format 'yyyy-MM-ddTHH:mm:ssZ')
}
[byte[]]$authVar = $Bytes
for ([int]$i = 7; $i -lt 16; $i++) {
    if ($authVar[$i] -ne 0) {
        throw "Invalid EFI time"
    }
}
Write-Output -InputObject (ToEfiTime -Bytes $authVar[0 .. 15])
