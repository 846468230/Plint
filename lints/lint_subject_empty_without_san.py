from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
RFC 5280: 4.2 & 4.2.1.6
Further, if the only subject identity included in the certificate is
an alternative name form (e.g., an electronic mail address), then the
subject distinguished name MUST be empty (an empty sequence), and the
subjectAltName extension MUST be present.  If the subject field
contains an empty sequence, then the issuing CA MUST include a
subjectAltName extension that is marked as critical.  When including
the subjectAltName extension in a certificate that has a non-empty
subject distinguished name, conforming CAs SHOULD mark the
subjectAltName extension as non-critical.
'''
class emptyWithoutSAN(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            if not c.subject:
                SANs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError as e:
            if str(e)=="The <ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)> extension is invalid and can't be parsed":
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_subject_empty_without_san","CAs MUST support subject alternative name if the subject field is an empty sequence","RFC 5280: 4.2 & 4.2.1.6",base.LintSource.RFC5280,Time.RFC2459Date,emptyWithoutSAN()))