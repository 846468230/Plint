from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.1d extendedKeyUsage
This extension MUST NOT be present.
'''
class rootCAKeyUsagePresent(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsRootCA(c)

    def Execute(self,c):
        try:
            KeyUsage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError as e:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_root_ca_key_usage_present","Root CA certificates MUST have Key Usage Extension Present","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.RFC2459Date,rootCAKeyUsagePresent()))