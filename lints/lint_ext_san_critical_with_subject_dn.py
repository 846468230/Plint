from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
Further, if the only subject identity included in the certificate is an
 alternative name form (e.g., an electronic mail address), then the subject
 distinguished name MUST be empty (an empty sequence), and the subjectAltName
 extension MUST be present. If the subject field contains an empty sequence,
 then the issuing CA MUST include a subjectAltName extension that is marked as
 critical. When including the subjectAltName extension in a certificate that
 has a non-empty subject distinguished name, conforming CAs SHOULD mark the
 subjectAltName extension as non-critical.
'''
class ExtSANCriticalWithSubjectDN(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            if san.critical and not len(c.suject):
                return base.LintResult(base.LintStatus.Warn)

            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        except AttributeError as e:
            if str(e) == "'_Certificate' object has no attribute 'suject'":
                return base.LintResult(base.LintStatus.Warn)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_ext_san_critical_with_subject_dn","If the subject contains a distinguished name, subjectAlternateName SHOULD be non-critical","RFC 5280: 4.2.1.6",base.LintSource.CABFBaselineRequirements,Time.RFC5280Date,ExtSANCriticalWithSubjectDN()))