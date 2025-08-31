# Example: Dell Inspiron 3847 / Windows 10

## Initial Secure Boot Changes

The secure boot configuration was updated by following Microsoft's [Mitigation deployment guidelines](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_mitigation_guidelines) for CVE-2023-24932. Afterwards, the secure boot configuration had the following certificates.

### PK certificate

The `PK` certificate, which should not have been used and has expired.

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

There was only one `KEK` certificate.

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

There were three certificates in `db`.

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

There was one certificate in `dbx` along with many hashes.
The certificate was also in `db`.

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

## Other Changes

Other changes to the certificates were made to resolve various issues.

### Replacing the PK Certificate

The non-production PK certificate needed to be replaced with a production PK certificate.
It seemed obvious that Dell was never going to provide a replacement PK certificate for their Inspiron 3847.
Although I could have created and managed my own private key and PK certificate, I did not want to do so.
Instead, I decided to use Microsoft's [Windows OEM Devices PK](https://www.microsoft.com/pkiops/oem/windows%20oem%20devices%20pk.cer) certificate:

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

The *Microsoft Corporation KEK CA 2011* certificate was still needed because Microsoft used it when signing the June 2025 `dbx` update.
With the certificate expiring in June 2026, I decided to add the newer [Microsoft Corporation KEK 2K CA 2023](https://www.microsoft.com/pkiops/certs/microsoft%20corporation%20kek%202k%20ca%202023.crt) certificate:

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
