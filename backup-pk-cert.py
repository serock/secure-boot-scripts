from colorama import Fore, Back, Style, init
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
from edk2toollib.os.uefivariablesupport import UefiVariable
from edk2toollib.uefi.authenticated_variables_structure_support import EfiSignatureDatabase, EfiSignatureDataFactory
from io import BytesIO

init()

try:
    uv = UefiVariable()
    uefiVar = uv.GetUefiVar(name="PK", guid="8be4df61-93ca-11d2-aa0d-00e098032b8c")
    if uefiVar[0] != 0:
        raise RuntimeError("Failed to get UEFI variable PK")

    with BytesIO(uefiVar[1]) as buffer:
        efiSigDb = EfiSignatureDatabase(buffer)
        efiSigList = efiSigDb.esl_list[0];
        if efiSigList.signature_type != EfiSignatureDataFactory.EFI_CERT_X509_GUID:
            raise ValueError(f"Unsupported signature type: {efiSigList.signature_type}")

        cert_data = efiSigList.signature_data_list[0].signature_data
        with open("PK.cer", "wb") as f:
            f.write(cert_data)

        problem = False
        cert = x509.load_der_x509_certificate(cert_data)
        subject_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if "DO NOT SHIP" in subject_name or "DO NOT TRUST" in subject_name:
            problem = True
            print(f"Saved the PK certificate, " + Fore.RED + Style.BRIGHT + f"{subject_name}" + Style.RESET_ALL + ", to PK.cer")
            print(Fore.RED + Style.BRIGHT + f"The PK certificate was issued with an untrusted key." + Style.RESET_ALL)
            print("  " + Fore.RED + "Go to https://www.kb.cert.org/vuls/id/455367 for more info." + Style.RESET_ALL)
        else:
            print(f"Saved the PK certificate, " + Fore.GREEN + Style.BRIGHT + f"{subject_name}" + Style.RESET_ALL + ", to PK.cer")

        expiration_date = cert.not_valid_after_utc.date()
        today = datetime.now(timezone.utc).date()
        date_delta = expiration_date - today
        if date_delta.days < 0:
            problem = True
            print(Fore.RED + Style.BRIGHT + f"The PK certificate expired on {expiration_date}." + Style.RESET_ALL)
        elif date_delta.days < 60:
            problem = True
            print("The PK certificate will expire on " + Fore.RED + Style.BRIGHT + f"{expiration_date}" + Style.RESET_ALL + ".")
        elif date_delta.days < 120:
            print("The PK certificate will expire on " + Fore.YELLOW + Style.BRIGHT + f"{expiration_date}" + Style.RESET_ALL + ".")
        else:
            print("The PK certificate will expire on " + Fore.GREEN + Style.BRIGHT + f"{expiration_date}" + Style.RESET_ALL + ".")

        if problem:
            print(Fore.RED + "Consider replacing the certificate with the " + Style.BRIGHT + "Windows OEM Devices PK" + Style.NORMAL + " certificate." + Style.RESET_ALL)
                    
except (RuntimeError, ValueError) as err:
    print(Fore.RED + Style.BRIGHT + f"ERROR: {err}" + Style.RESET_ALL)
