# Example: Dell Inspiron 3847 / Windows 10

The secure boot configuration was updated by following the [Mitigation deployment guidelines](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_mitigation_guidelines) for CVE-2023-24932.

## PK certificate

Not only did Dell use an insecure Platform Key, the `PK` certificate expired in 2018.

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

## KEK certificate

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

## Certificates in db

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

## Certificates in dbx

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
