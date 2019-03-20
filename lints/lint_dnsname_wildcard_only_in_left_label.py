from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,fqdn,gtld
import tldextract
from cryptography.hazmat.primitives.asymmetric import dsa

class DNSNameWildcardOnlyInLeftlabel(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return True
    
    def  wildcardNotInLeftLabel(self,domain):
        lables = domain.split(".")
        if len(lables) > 1:
            for lable in lables[1:]:
                if "*" in lable:
                    return True
        return False
        
    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)):
                for name in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    if self.wildcardNotInLeftLabel(name.value) :
                        return base.LintResult(base.LintStatus.Error)
            
            for dns in c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName):
                if self.wildcardNotInLeftLabel(dns):
                    return base.LintResult(base.LintStatus.Error)

            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.NA)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
            


def init():
    base.RegisterLint(base.Lint("e_dnsname_wildcard_only_in_left_label","DNSName should not have wildcards except in the left-most label","BRs: 7.1.4.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,DNSNameWildcardOnlyInLeftlabel()))