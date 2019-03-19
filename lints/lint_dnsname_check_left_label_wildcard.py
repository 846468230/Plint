from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid
from cryptography.hazmat.primitives.asymmetric import dsa

class DNSNameLeftLabelWildcardCheck(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return True
    
    def wildcardInLeftLabelIncorrect(self,domain):
        labels = domain.split(".")
        if len(labels) >= 1:
            leftLable = labels[0]
            if "*" in leftLable and leftLable !="*":
                return True
        return False

    def Execute(self,c):
        try:
            for name in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                if self.wildcardInLeftLabelIncorrect(name.value):
                    return base.LintResult(base.LintStatus.Error)
            
            for dns in c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName):
                if self.wildcardInLeftLabelIncorrect(dns):
                    return base.LintResult(base.LintStatus.Error)
            
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_dnsname_left_label_wildcard_correct","Wildcards in the left label of DNSName should only be *","BRs: 7.1.4.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,DNSNameLeftLabelWildcardCheck()))