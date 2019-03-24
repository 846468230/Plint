from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
The freshest CRL extension identifies how delta CRL information is obtained. The extension MUST be marked as non-critical by conforming CAs. Further discussion of CRL management is contained in Section 5.
'''
class ExtFreshestCrlMarkedCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.FRESHEST_CRL)

    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).critical:
                return  base.LintResult(base.LintStatus.Error) 
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_freshest_crl_marked_critical","Freshest CRL MUST be marked as non-critical by conforming CAs","RFC 5280: 4.2.1.15",base.LintSource.RFC5280,Time.RFC3280Date,ExtFreshestCrlMarkedCritical()))