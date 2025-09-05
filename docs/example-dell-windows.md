# Example: Dell Inspiron 3847 / Windows 10 Home edition

## Initial Secure Boot Changes

I updated the secure boot configuration by following Microsoft's [Mitigation deployment guidelines](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_mitigation_guidelines) for CVE-2023-24932.

## Saving Secure Boot Certificates

Running PowerShell as Administrator, I saved the secure boot certificates.

```powershell
if (-not (Test-Path -Path 'C:\secure-boot\backup')) {New-Item -Path 'C:\secure-boot\backup' -ItemType Directory}
Set-Location -Path 'C:\secure-boot\backup'

Invoke-WebRequest -Uri 'https://github.com/serock/secure-boot-scripts/raw/60aa92bb122a6c40bf5e7b89a20f3c5f89bcd491/powershell/Save-PKCert.ps1'   -OutFile 'Save-PKCert.ps1'
Invoke-WebRequest -Uri 'https://github.com/serock/secure-boot-scripts/raw/60aa92bb122a6c40bf5e7b89a20f3c5f89bcd491/powershell/Save-KEKCerts.ps1' -OutFile 'Save-KEKCerts.ps1'

if ((Get-ExecutionPolicy) -in 'AllSigned','Restricted') {Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process}

if ((Get-ExecutionPolicy) -eq 'RemoteSigned') {Unblock-File -Path '.\Save-PKCert.ps1','.\Save-KEKCerts.ps1'}

.\Save-PKCert.ps1
.\Save-KEKCerts.ps1
```

The following secure boot certificates were saved.

### PK certificate

The PK certificate, which clearly should not have been shipped by Dell and expired in 2018, was not changed by following the *Mitigation deployment guidelines* mentioned above.

```
Version: 3 (0x2)
Serial Number:
    45:18:b4:22:4e:57:12:8b:44:18:25:a1:f4:5e:81:1d
Signature Algorithm: sha256WithRSAEncryption
Issuer: CN = Root Agency
Validity
    Not Before: Aug  6 13:03:41 2013 GMT
    Not After : Aug  6 13:03:40 2018 GMT
Subject: CN = DO NOT SHIP - PK
```

### KEK certificate

The one KEK certificate was not changed by following the *Mitigation deployment guidelines*.

```
Version: 3 (0x2)
Serial Number:
    61:0a:d1:88:00:00:00:00:00:03
Signature Algorithm: sha256WithRSAEncryption
Issuer: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Corporation Third Party Marketplace Root
Validity
    Not Before: Jun 24 20:41:29 2011 GMT
    Not After : Jun 24 20:51:29 2026 GMT
Subject: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Corporation KEK CA 2011
```

### Certificates in db

Of the three certificates in db, only the **Windows UEFI CA 2023** certificate was added by following the *Mitigation deployment guidelines*; the other two certificates were not changed.

```
[1]:

Version: 3 (0x2)
Serial Number:
    61:07:76:56:00:00:00:00:00:08
Signature Algorithm: sha256WithRSAEncryption
Issuer: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Root Certificate Authority 2010
Validity
    Not Before: Oct 19 18:41:42 2011 GMT
    Not After : Oct 19 18:51:42 2026 GMT
Subject: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Windows Production PCA 2011

[2]:

Version: 3 (0x2)
Serial Number:
    61:08:d3:c4:00:00:00:00:00:04
Signature Algorithm: sha256WithRSAEncryption
Issuer: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Corporation Third Party Marketplace Root
Validity
    Not Before: Jun 27 21:22:45 2011 GMT
    Not After : Jun 27 21:32:45 2026 GMT
Subject: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Corporation UEFI CA 2011

[3]:

Version: 3 (0x2)
Serial Number:
    33:00:00:00:1a:88:8b:98:00:56:22:84:c1:00:00:00:00:00:1a
Signature Algorithm: sha256WithRSAEncryption
Issuer: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Root Certificate Authority 2010
Validity
    Not Before: Jun 13 18:58:29 2023 GMT
    Not After : Jun 13 19:08:29 2035 GMT
Subject: C = US, O = Microsoft Corporation, CN = Windows UEFI CA 2023
```

### Certificates in dbx

The only certificate in dbx, **Microsoft Windows Production PCA 2011**, was added by following the *Mitigation deployment guidelines*.
This certificate was also in db.

```
Version: 3 (0x2)
Serial Number:
    61:07:76:56:00:00:00:00:00:08
Signature Algorithm: sha256WithRSAEncryption
Issuer: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Root Certificate Authority 2010
Validity
    Not Before: Oct 19 18:41:42 2011 GMT
    Not After : Oct 19 18:51:42 2026 GMT
Subject: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Windows Production PCA 2011
```

## Planning Other Secure Boot Certificate Changes to be Applied Manually

Other changes to the certificates were made to resolve various issues.

### Replacing the PK Certificate

The non-production PK certificate needed to be replaced with a production PK certificate.
It was clear that Dell was never going to provide a replacement PK certificate for the Inspiron 3847.
Although I could have created and managed my own private key and PK certificate, I decided instead to replace the old PK certificate with Microsoft's **Windows OEM Devices PK** certificate because doing that was less work for me.

```
Version: 3 (0x2)
Serial Number:
    33:00:00:00:14:e8:c8:38:de:de:04:4e:a7:00:00:00:00:00:14
Signature Algorithm: sha256WithRSAEncryption
Issuer: C = US, O = Microsoft Corporation, CN = Microsoft RSA Third Party PCA 2023
Validity
    Not Before: Sep 21 20:28:26 2023 GMT
    Not After : Sep 18 20:28:26 2038 GMT
Subject: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Windows OEM Devices PK
```

### Adding a Newer KEK Certificate

The **Microsoft Corporation KEK CA 2011** certificate was still needed because Microsoft used it when signing the June 2025 `dbx` update, which was the latest update available in August 2025.
With the certificate expiring in June 2026, I decided to add the newer **Microsoft Corporation KEK 2K CA 2023** certificate:

```
        Version: 3 (0x2)
        Serial Number:
            33:00:00:00:13:14:16:b8:61:6d:82:82:4b:00:00:00:00:00:13
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Microsoft Corporation, CN = Microsoft RSA Devices Root CA 2021
        Validity
            Not Before: Mar  2 20:21:35 2023 GMT
            Not After : Mar  2 20:31:35 2038 GMT
        Subject: C = US, O = Microsoft Corporation, CN = Microsoft Corporation KEK 2K CA 2023
```

### Updating Certificates in db

TODO: add documentation

## Applying the Other Secure Boot Certificate Changes

Dell has not made available a download of Microsoft's **Windows OEM Devices PK** certificate that is signed with the private key for the default PK.
To enroll a PK that is not signed (i.e., not authenticated), the Secure Boot mode needs to be changed to Setup Mode.
Changing to Setup Mode is accomplished by entering the BIOS Setup utility and clearing the Secure Boot keys:

1. Reboot
2. Press the F2 key repeatedly before the Dell logo appears until the BIOS Setup utility appears.
3. Under the **Boot** tab, select **Clear Secure Boot Keys**.
4. Press the F10 key to save and exit.

TODO: add documentation

```powershell
Set-Location -Path 'C:\secure-boot'

Invoke-WebRequest -Uri 'https://github.com/microsoft/secureboot_objects/raw/b28f4bb39ad9567b183fb59d8cdc051df7d24472/scripts/windows/InstallSecureBootKeys.ps1' -OutFile 'InstallSecureBootKeys.ps1'

Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=321185'  -OutFile 'MicCorKEKCA2011-2011-06-24.der'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=321192'  -OutFile 'MicWinProPCA2011-2011-10-19.der'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=321194'  -OutFile 'MicCorUEFCA2011-2011-06-27.der'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2239775' -OutFile 'microsoft-corporation-kek-2k-ca-2023.der'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2239776' -OutFile 'windows-uefi-ca-2023.der'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2239872' -OutFile 'microsoft-uefi-ca-2023.der'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2255361' -OutFile 'windows-oem-devices-pk.der'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2284009' -OutFile 'microsoft-option-rom-uefi-ca-2023.der'

Format-SecureBootUEFI -Name dbx -ContentFilePath 'DBX.bin' -SignatureOwner '00000000-0000-0000-0000-000000000000' -Hash '0000000000000000000000000000000000000000000000000000000000000000' -Algorithm SHA256
Format-SecureBootUEFI -Name db  -ContentFilePath 'DB.bin'  -SignatureOwner '77fa9abd-0359-4d32-bd60-28f4e78f784b' -FormatWithCert -CertificateFilePath 'windows-uefi-ca-2023.der','microsoft-uefi-ca-2023.der','microsoft-option-rom-uefi-ca-2023.der'
Format-SecureBootUEFI -Name KEK -ContentFilePath 'KEK.bin' -SignatureOwner '77fa9abd-0359-4d32-bd60-28f4e78f784b' -FormatWithCert -CertificateFilePath 'MicCorKEKCA2011-2011-06-24.der','microsoft-corporation-kek-2k-ca-2023.der'
Format-SecureBootUEFI -Name PK  -ContentFilePath 'PK.bin'  -SignatureOwner '77fa9abd-0359-4d32-bd60-28f4e78f784b' -FormatWithCert -CertificateFilePath 'windows-oem-devices-pk.der'
```

TODO: add documentation

```powershell
if ((Get-ExecutionPolicy) -eq 'RemoteSigned') {Unblock-File -Path '.\InstallSecureBootKeys.ps1'}

.\InstallSecureBootKeys.ps1 -PresignedObjectsPath 'C:\secure-boot'

```
