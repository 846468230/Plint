from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,fqdn,gtld
from cryptography.hazmat.primitives.asymmetric import dsa

class DNSNameLabelLengthTooLong(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and fqdn.DNSNamesExist(c)
    
    def labelLengthTooLong(self,domain):
        labels = domain.split(".")
        for label in labels:
            if len(label) > 63:
                return True
        return False

    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) and not fqdn.CommonNameIsIP(c):
                for name in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    if self.labelLengthTooLong(name.value) :
                        return base.LintResult(base.LintStatus.Error)
            
            for dns in c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName):
                if self.labelLengthTooLong(dns):
                    return base.LintResult(base.LintStatus.Error)

            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_dnsname_label_too_long","DNSName labels MUST be less than or equal to 63 characters","RFC 1035",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,DNSNameLabelLengthTooLong()))