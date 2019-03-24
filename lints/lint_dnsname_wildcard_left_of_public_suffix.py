from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,fqdn,gtld
import tldextract
from cryptography.hazmat.primitives.asymmetric import dsa

class DNSNameWildcardLeftofPublicSuffix(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and fqdn.DNSNamesExist(c)
    
    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) and not fqdn.CommonNameIsIP(c):
                for name in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    if "*" == tldextract.extract(name.value).domain :
                        return base.LintResult(base.LintStatus.Warn)
            
            for dns in c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName):
                if "*" == tldextract.extract(dns).domain:
                    return base.LintResult(base.LintStatus.Warn)

            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.NA)
        except x509.ExtensionNotFound as e:
            if str(e) == "No <ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)> extension was found":
                return base.LintResult(base.LintStatus.Pass)      


def init():
    base.RegisterLint(base.Lint("w_dnsname_wildcard_left_of_public_suffix","the CA MUST establish and follow a documented procedure[^pubsuffix] that determines if the wildcard character occurs in the first label position to the left of a “registry‐controlled” label or “public suffix”","BRs: 3.2.2.6",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,DNSNameWildcardLeftofPublicSuffix()))