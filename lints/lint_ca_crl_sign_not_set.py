from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.1b
This extension MUST be present and MUST be marked critical. Bit positions for
keyCertSign and cRLSign MUST be set. If the Root CA Private Key is used for
signing OCSP responses, then the digitalSignature bit MUST be set.
'''
class caCRLSignNotSet(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsCACert(c) and ca.IsExtInCert(c,ExtensionOID.KEY_USAGE)

    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.crl_sign:
                return  base.LintResult(base.LintStatus.Pass) 
            else:
                return  base.LintResult(base.LintStatus.Error)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)

def init():
    base.RegisterLint(base.Lint("e_ca_crl_sign_not_set","Root and Subordinate CA certificate keyUsage extension's crlSign bit MUST be set","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,caCRLSignNotSet()))