from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.3
keyUsage (optional)
If present, bit positions for keyCertSign and cRLSign MUST NOT be set.
'''
class subCrlSignAllowed(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and ca.IsExtInCert(c,ExtensionOID.KEY_USAGE)

    def Execute(self,c):
        try:
            KeyUsages = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if KeyUsages.crl_sign:
                return base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_key_usage_crl_sign_bit_set","Subscriber Certificate: keyUsage if present, bit positions for keyCertSign and cRLSign MUST NOT be set.","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCrlSignAllowed()))