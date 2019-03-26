from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
RFC 5280: 4.2.1.9
The cA boolean indicates whether the certified public key may be used
   to verify certificate signatures.  If the cA boolean is not asserted,
   then the keyCertSign bit in the key usage extension MUST NOT be
   asserted.  If the basic constraints extension is not present in a
   version 3 certificate, or the extension is present but the cA boolean
   is not asserted, then the certified public key MUST NOT be used to
   verify certificate signatures.
'''
class keyUsageCertSignNoCa(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.KEY_USAGE)

    def Execute(self,c):
        try:
            KeyUsage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if KeyUsage.key_cert_sign:
                try:
                    BasicCon = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                    if ca.IsCACert(c):
                        return  base.LintResult(base.LintStatus.Pass)
                    else:
                        return  base.LintResult(base.LintStatus.Error)
                except x509.ExtensionNotFound:
                    return  base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("e_ext_key_usage_cert_sign_without_ca","if the keyCertSign bit is asserted, then the cA bit in the basic constraints extension MUST also be asserted","RFC 5280: 4.2.1.3 & 4.2.1.9",base.LintSource.RFC5280,Time.RFC5280Date,keyUsageCertSignNoCa()))