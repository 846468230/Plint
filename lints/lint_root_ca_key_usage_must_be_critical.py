from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.1d extendedKeyUsage
This extension MUST NOT be present.
'''
class rootCAKeyUsageMustBeCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsRootCA(c) and ca.IsExtInCert(c,ExtensionOID.KEY_USAGE)

    def Execute(self,c):
        try:
            KeyUsage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            if KeyUsage.critical:
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError as e:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_root_ca_key_usage_must_be_critical","Root CA certificates MUST have Key Usage Extension marked critical","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.RFC2459Date,rootCAKeyUsageMustBeCritical()))