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
    uefiVar = uv.GetUefiVar(name="KEK", guid="8be4df61-93ca-11d2-aa0d-00e098032b8c")
    if uefiVar[0] != 0:
        raise RuntimeError("Failed to get UEFI variable KEK")

    problem = True
    microsoft_kek_2023_cert_name = "Microsoft Corporation KEK 2K CA 2023"
    with BytesIO(uefiVar[1]) as buffer:
        efiSigDb = EfiSignatureDatabase(buffer)
        i = 0
        for esl in efiSigDb.esl_list:
            if esl.signature_type != EfiSignatureDataFactory.EFI_CERT_X509_GUID:
                raise ValueError(f"Unsupported signature type: {efiSigList.signature_type}")

            cert_data = esl.signature_data_list[0].signature_data
            with open(f"KEK{i}.cer", "wb") as f:
                f.write(cert_data)

            cert = x509.load_der_x509_certificate(cert_data)
            subject_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if subject_name == microsoft_kek_2023_cert_name:
                problem = false
            print(f"Saved the KEK cert, {Style.BRIGHT}{subject_name}{Style.RESET_ALL}, to KEK{i}.cer")

            expiration_date = cert.not_valid_after_utc.date()
            today = datetime.now(timezone.utc).date()
            date_delta = expiration_date - today
            if date_delta.days < 0:
                print(f"  {Fore.RED}{Style.BRIGHT}This KEK cert expired on {expiration_date}.{Style.RESET_ALL}")
                print(f"  {Fore.RED}Consider removing this KEK cert.{Style.RESET_ALL}")
            elif date_delta.days < 60:
                print(f"  This KEK cert will expire on {Fore.RED}{Style.BRIGHT}{expiration_date}{Style.RESET_ALL}.")
            elif date_delta.days < 120:
                print(f"  This KEK cert will expire on {Fore.YELLOW}{Style.BRIGHT}{expiration_date}{Style.RESET_ALL}.")
            else:
                print(f"  This KEK cert will expire on {Fore.GREEN}{Style.BRIGHT}{expiration_date}{Style.RESET_ALL}.")
            i += 1

        if problem:
            print(f"{Fore.RED}Consider adding the {Style.BRIGHT}{microsoft_kek_2023_cert_name}{Style.NORMAL} cert.{Style.RESET_ALL}")
                    
except (RuntimeError, ValueError) as err:
    print(f"{Fore.RED}{Style.BRIGHT}ERROR: {err}{Style.RESET_ALL}")
