from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,fqdn,gtld
import tldextract
from cryptography.hazmat.primitives.asymmetric import dsa

class DNSNameUnderscoreInSLD(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and fqdn.DNSNamesExist(c)
    
    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) and not fqdn.CommonNameIsIP(c):
                for name in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    if "_" in tldextract.extract(name.value).domain :
                        return base.LintResult(base.LintStatus.Error)
            
            for dns in c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName):
                if "_" in tldextract.extract(dns).domain:
                    return base.LintResult(base.LintStatus.Error)

            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.NA)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)    


def init():
    base.RegisterLint(base.Lint("e_dnsname_underscore_in_sld","DNSName should not have underscore in SLD","BRs: 7.1.4.2",base.LintSource.CABFBaselineRequirements,Time.RFC5280Date,DNSNameUnderscoreInSLD()))