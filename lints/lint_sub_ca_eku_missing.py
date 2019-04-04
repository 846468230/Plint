from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
'''
class subCAEKUMissing(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubCA(c)

    def Execute(self,c):
        try:
            extendKeyUsage = c.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            return  base.LintResult(base.LintStatus.Pass) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Notice)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("n_sub_ca_eku_missing","To be considered Technically Constrained, the Subordinate CA certificate MUST have extkeyUsage extension","BRs: 7.1.5",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCAEKUMissing()))