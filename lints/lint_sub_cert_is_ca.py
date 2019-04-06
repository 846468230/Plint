from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid
'''
'''
class subCertNotCA(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        try:
            if ca.IsExtInCert(c,ExtensionOID.KEY_USAGE):
                KeyUsage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if not KeyUsage.key_cert_sign and ca.IsExtInCert(c,ExtensionOID.BASIC_CONSTRAINTS):
                    return True
            return False
        except ValueError:
            return True

    def Execute(self,c):
        try:
            BasicConstraints = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if BasicConstraints.ca:
                return base.LintResult(base.LintStatus.Error)
            else:
                return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_not_is_ca","Subscriber Certificate: basicContrainsts cA field MUST NOT be true.","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCertNotCA()))