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
class caDigSignNotSet(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsCACert(c) and ca.IsExtInCert(c,ExtensionOID.KEY_USAGE)

    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature:
                return  base.LintResult(base.LintStatus.Pass) 
            else:
                return  base.LintResult(base.LintStatus.Notice)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Notice)

def init():
    base.RegisterLint(base.Lint("n_ca_digital_signature_not_set","Root and Subordinate CA Certificates that wish to use their private key for signing OCSP responses will not be able to without their digital signature set","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,caDigSignNotSet()))