from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
Issuer Alternative Name
   As with Section 4.2.1.6, this extension is used to associate Internet style identities with the certificate issuer. Issuer alternative name MUST be encoded as in 4.2.1.6.  Issuer alternative names are not processed as part of the certification path validation algorithm in Section 6. (That is, issuer alternative names are not used in name chaining and name constraints are not enforced.)
   Where present, conforming CAs SHOULD mark this extension as non-critical.
'''
class ExtIANCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.ISSUER_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME).critical:
                return  base.LintResult(base.LintStatus.Warn) 
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_ext_ian_critical","Issuer alternate name should be marked as non-critical","RFC 5280: 4.2.1.7",base.LintSource.RFC5280,Time.RFC2459Date,ExtIANCritical()))