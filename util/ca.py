from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID
from cryptography.x509 import ExtensionNotFound
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa,dsa,ec
def  IsServerAuthCert(cert):
    try:
        extKeyUsages=cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except:
        return True
    for extKeyUsage in extKeyUsages.value:  
        if ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE == extKeyUsage or ExtendedKeyUsageOID.SERVER_AUTH == extKeyUsage:
            return True
    return False

def IsSelfSigned(cert):
    key = cert.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
            return True
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(cert.signature,cert.tbs_certificate_bytes,cert.signature_hash_algorithm)
            return True
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature,cert.tbs_certificate_bytes,cert.signature_hash_algorithm)
            return True
        else:
            return False
    except InvalidSignature:
        return False

def IsSubscriberCert(cert):
    return not IsCACert(cert) and not IsSelfSigned(cert)


def IsExtInCert(cert, oid):
    try:
        cert.extensions.get_extension_for_oid(oid)
        return True
    except ExtensionNotFound:
        return False
    except ValueError:
        return True
def IsCACert(c):
    try:
        basic_constraint=c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except:
        return False
    try:
        return basic_constraint.value.ca
    except:
        return False