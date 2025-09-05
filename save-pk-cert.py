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
    uefi_var = uv.GetUefiVar(name="PK", guid="8be4df61-93ca-11d2-aa0d-00e098032b8c")
    if uefi_var[0] != 0:
        raise RuntimeError("Failed to get UEFI variable PK")

    with BytesIO(uefi_var[1]) as buffer:
        efi_sig_db = EfiSignatureDatabase(buffer)
        efi_sig_list = efi_sig_db.esl_list[0];
        if efi_sig_list.signature_type != EfiSignatureDataFactory.EFI_CERT_X509_GUID:
            raise ValueError(f"Unsupported signature type: {efiSigList.signature_type}")

        cert_data = efi_sig_list.signature_data_list[0].signature_data
        with open("PK0.der", "wb") as f:
            f.write(cert_data)

        cert = x509.load_der_x509_certificate(cert_data)
        subject_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        expiration_time = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        time_delta = expiration_time - now

        bad_cert = "DO NOT SHIP" in subject_name or "DO NOT TRUST" in subject_name
        cert_expired = expiration_time < now

        style_subject_name = f"{Fore.RED}{Style.BRIGHT}" if bad_cert or cert_expired else f"{Fore.GREEN}{Style.BRIGHT}"
        print(f"Saved the PK cert, {style_subject_name}{subject_name}{Style.RESET_ALL}, to PK0.der")

        if bad_cert:
            print(f"  {Fore.RED}{Style.BRIGHT}This PK cert was issued with an untrusted key{Style.RESET_ALL}")
            print(f"  {Fore.RED}Go to https://www.kb.cert.org/vuls/id/455367 for more info{Style.RESET_ALL}")

        if time_delta.days < 60:
            style_expiration = f"{Fore.RED}{Style.BRIGHT}"
        elif time_delta.days < 120:
            style_expiration = f"{Fore.YELLOW}{Style.BRIGHT}"
        else:
            style_expiration = f"{Fore.GREEN}{Style.BRIGHT}"

        if cert_expired:
            print(f"  {Fore.RED}{Style.BRIGHT}This PK cert expired on {expiration_time.date()}{Style.RESET_ALL}")
        else:
            print(f"  This PK cert will expire on {style_expiration}{expiration_time.date()}{Style.RESET_ALL}")

        print(f"  The signature owner is {efi_sig_list.signature_data_list[0].signature_owner}")

        should_replace_cert = bad_cert or time_delta.days < 60

        if should_replace_cert:
            print(f"  {Fore.RED}Consider replacing this cert with the {Style.BRIGHT}Windows OEM Devices PK{Style.NORMAL} cert{Style.RESET_ALL}")
                    
except (RuntimeError, ValueError) as err:
    print(f"{Fore.RED}{Style.BRIGHT}ERROR: {err}{Style.RESET_ALL}")
