from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,NameOID
from util.time import Time
from util import ca,fqdn
import re


class DNSNameProperCharacters(base.LintInterface):
    def __init__(self):
        self.CompiledExpression=""

    def Initialize(self):
        dnsNameRegexp="^(\*\.)?(\?\.)*([A-Za-z0-9*_-]+\.)*[A-Za-z0-9*_-]*$"
        self.CompiledExpression=re.compile(dnsNameRegexp)
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and fqdn.DNSNamesExist(c)
    
    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) and not fqdn.CommonNameIsIP(c):
                for name in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    if not self.CompiledExpression.match(name.value):
                        return base.LintResult(base.LintStatus.Error)
            
            for dns in c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName):
                if not self.CompiledExpression.match(dns):
                    return base.LintResult(base.LintStatus.Error)

            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
        except x509.ExtensionNotFound:
            return base.LintResult(base.LintStatus.Pass)
            
def init():
    base.RegisterLint(base.Lint("e_dnsname_bad_character_in_label","Characters in labels of DNSNames MUST be alphanumeric, - , _ or *","BRs: 7.1.4.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,DNSNameProperCharacters()))