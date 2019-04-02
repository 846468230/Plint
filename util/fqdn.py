from cryptography.x509 import NameOID,ExtensionOID
from cryptography import x509
import ipaddress
def CommonNameIsIP(cert):
    commonname=cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    for dns in commonname:
        try:
            ipaddress.ip_address(dns.value)
        except ValueError:
            return False
    return True
# is the combine with the romve and determine 
def isRedactedCertificate(domain):
    if domain.value =="":
        return False
    return  "?." in domain.value[:4]

def DNSNamesExist(cert):
    if not len(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)):
        try: 
            if not len(cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)):
                return False
            else:
                return True
        except x509.ExtensionNotFound:
            return False
    else:
        return True
