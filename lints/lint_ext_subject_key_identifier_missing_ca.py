from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
 To facilitate certification path construction, this extension MUST
   appear in all conforming CA certificates, that is, all certificates
   including the basic constraints extension (Section 4.2.1.9) where the
   value of cA is TRUE.  In conforming CA certificates, the value of the
   subject key identifier MUST be the value placed in the key identifier
   field of the authority key identifier extension (Section 4.2.1.1) of
   certificates issued by the subject of this certificate.  Applications
   are not required to verify that key identifiers match when performing
   certification path validation.
   ...
   For end entity certificates, the subject key identifier extension provides
   a means for identifying certificates containing the particular public key
   used in an application. Where an end entity has obtained multiple certificates,
   especially from multiple CAs, the subject key identifier provides a means to
   quickly identify the set of certificates containing a particular public key.
   To assist applications in identifying the appropriate end entity certificate,
   this extension SHOULD be included in all end entity certificates.
'''
class subjectKeyIdMissingCA(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsCACert(c)

    def Execute(self,c):
        try:
            SDCs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER) 
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_subject_key_identifier_missing_ca","CAs MUST include a Subject Key Identifier in all CA certificates","RFC 5280: 4.2 & 4.2.1.2",base.LintSource.RFC5280,Time.RFC2459Date,subjectKeyIdMissingCA()))