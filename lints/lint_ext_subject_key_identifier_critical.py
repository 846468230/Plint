from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.2.1.2
 Conforming CAs MUST mark this extension as non-critical.
'''
class subjectKeyIdCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_KEY_IDENTIFIER)

    def Execute(self,c):
        try:
            SDCs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if SDCs.critical:
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_subject_key_identifier_critical","The subject key identifier extension MUST be non-critical","RFC 5280: 4.2.1.2",base.LintSource.RFC5280,Time.RFC2459Date,subjectKeyIdCritical()))