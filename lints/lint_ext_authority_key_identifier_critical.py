from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta
'''
RFC 5280: 4.2.1.1
Conforming CAs MUST mark this extension as non-critical.
'''

class authorityKeyIdCritical(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsExtInCert(c,oid.AuthkeyOID)
    
    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).critical:
                return  base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ext_authority_key_identifier_critical","The authority key identifier extension must be non-critical","RFC 5280: 4.2.1.1",base.LintSource.RFC5280,Time.RFC2459Date,authorityKeyIdCritical()))