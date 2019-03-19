from cryptography.x509 import ObjectIdentifier,ExtensionNotFound
from cryptography.x509.oid import ExtensionOID


#extension OIDs
AiaOID                  = ObjectIdentifier("1.3.6.1.5.5.7.1.1")        # Authority Information Access
AuthkeyOID              = ObjectIdentifier("2.5.29.35")                     # Authority Key Identifier
BasicConstOID           = ObjectIdentifier("2.5.29.19")                     # Basic Constraints
CertPolicyOID           = ObjectIdentifier("2.5.29.32")                     # Certificate Policies
CrlDistOID              = ObjectIdentifier("2.5.29.31")                     # CRL Distribution Points
CtPoisonOID             = ObjectIdentifier("1.3.6.1.5.1.11129.2.4.3") # CT Poison
EkuSynOid               = ObjectIdentifier("2.5.29.37")                     # Extended Key Usage Syntax
FreshCRLOID             = ObjectIdentifier("2.5.29.46")                     # Freshest CRL
InhibitAnyPolicyOID     = ObjectIdentifier("2.5.29.54")                     # Inhibit Any Policy
IssuerAlternateNameOID  = ObjectIdentifier("2.5.29.18")                     # Issuer Alt Name
KeyUsageOID             = ObjectIdentifier("2.5.29.15")                     # Key Usage
LogoTypeOID             = ObjectIdentifier("1.3.6.1.5.5.7.1.12")       # Logo Type Ext
NameConstOID            = ObjectIdentifier("2.5.29.30")                     # Name Constraints
OscpNoCheckOID          = ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")    # OSCP No Check
PolicyConstOID          = ObjectIdentifier("2.5.29.36")                     # Policy Constraints
PolicyMapOID            = ObjectIdentifier("2.5.29.33")                     # Policy Mappings
PrivKeyUsageOID         = ObjectIdentifier("2.5.29.16")                     # Private Key Usage Period
QcStateOid              = ObjectIdentifier("1.3.6.1.5.5.7.1.3")        # QC Statements
TimestampOID            = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2") # Signed Certificate Timestamp List
SmimeOID                = ObjectIdentifier("1.2.840.113549.1.9.15")      # Smime Capabilities
SubjectAlternateNameOID = ObjectIdentifier("2.5.29.17")                     # Subject Alt Name
SubjectDirAttrOID       = ObjectIdentifier("2.5.29.9")                      # Subject Directory Attributes
SubjectInfoAccessOID    = ObjectIdentifier("1.3.6.1.5.5.7.1.11")       # Subject Info Access Syntax
SubjectKeyIdentityOID   = ObjectIdentifier("2.5.29.14")                     # Subject Key Identifier
# CA/B reserved policies
BRDomainValidatedOID       = ObjectIdentifier("2.23.140.1.2.1") # CA/B BR Domain-Validated
BROrganizationValidatedOID = ObjectIdentifier("2.23.140.1.2.2") # CA/B BR Organization-Validated
BRIndividualValidatedOID   = ObjectIdentifier("2.23.140.1.2.3") # CA/B BR Individual-Validated
#X.500 attribute types
CommonNameOID             = ObjectIdentifier("2.5.4.3")
SurnameOID                = ObjectIdentifier("2.5.4.4")
SerialOID                 = ObjectIdentifier("2.5.4.5")
CountryNameOID            = ObjectIdentifier("2.5.4.6")
LocalityNameOID           = ObjectIdentifier("2.5.4.7")
StateOrProvinceNameOID    = ObjectIdentifier("2.5.4.8")
StreetAddressOID          = ObjectIdentifier("2.5.4.9")
OrganizationNameOID       = ObjectIdentifier("2.5.4.10")
OrganizationalUnitNameOID = ObjectIdentifier("2.5.4.11")
BusinessOID               = ObjectIdentifier("2.5.4.15")
PostalCodeOID             = ObjectIdentifier("2.5.4.17")
GivenNameOID              = ObjectIdentifier("2.5.4.42")
#other OIDs
OidRSASSAPSS  = ObjectIdentifier("1.2.840.113549.1.1.10")
AnyPolicyOID  = ObjectIdentifier("2.5.29.32.0")
UserNoticeOID = ObjectIdentifier("1.3.6.1.5.5.7.2.2")
CpsOID        = ObjectIdentifier("1.3.6.1.5.5.7.2.1")

def SliceContainsOID(c,oid):
    try:
        extension=c.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        for item in extension.value:
            if item.policy_identifier==oid:
                return True
        return False
    except ExtensionNotFound:
        return False
    except ValueError:
        return False

def TypeInName(names,oid):
    for name in names:
        if name.oid==oid:
            return True
    return False