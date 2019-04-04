from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID
from util.time import Time
from util import ca
'''
'''
class subCAEKUValidFields(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubCA(c) and ca.IsExtInCert(c,ExtensionOID.EXTENDED_KEY_USAGE)

    def Execute(self,c):
        try:
            extendKeyUsages = c.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            for extendKeyUsage in extendKeyUsages:
                if extendKeyUsage == ExtendedKeyUsageOID.SERVER_AUTH or extendKeyUsage == ExtendedKeyUsageOID.CLIENT_AUTH:
                    return  base.LintResult(base.LintStatus.Pass) 
            return  base.LintResult(base.LintStatus.Notice)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("n_sub_ca_eku_not_technically_constrained","Subordinate CA extkeyUsage, either id-kp-serverAuth or id-kp-clientAuth or both values MUST be present to be technically constrained.","BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABV116Date,subCAEKUValidFields()))