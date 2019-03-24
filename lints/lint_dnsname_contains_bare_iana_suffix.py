from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,fqdn,gtld
from cryptography.hazmat.primitives.asymmetric import dsa

class dnsNameContainsBareIANASuffix(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and fqdn.DNSNamesExist(c)
    
    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) and not fqdn.CommonNameIsIP(c):
                for name in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    if gtld.IsInTLDMap(name.value):
                        return base.LintResult(base.LintStatus.Error)
            
            for dns in c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName):
                if gtld.IsInTLDMap(dns):
                    return base.LintResult(base.LintStatus.Error)

            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
        except x509.ExtensionNotFound as e:
            if str(e) == "No <ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)> extension was found":
                return base.LintResult(base.LintStatus.Pass)
            
def init():
    base.RegisterLint(base.Lint("e_dnsname_contains_bare_iana_suffix","DNSNames should not contain a bare IANA suffix.","BRs: 7.1.4.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,dnsNameContainsBareIANASuffix()))