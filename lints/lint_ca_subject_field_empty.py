from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.1.2.6
The subject field identifies the entity associated with the public
   key stored in the subject public key field.  The subject name MAY be
   carried in the subject field and/or the subjectAltName extension.  If
   the subject is a CA (e.g., the basic constraints extension, as
   discussed in Section 4.2.1.9, is present and the value of cA is
   TRUE), then the subject field MUST be populated with a non-empty
   distinguished name matching the contents of the issuer field (Section
   4.1.2.4) in all certificates issued by the subject CA.
'''
class caSubjectEmpty(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsCACert(c)
    
    def Execute(self,c):
        try:
            if len(c.subject):
                for attribute in c.subject:
                    if attribute.value:
                        return base.LintResult(base.LintStatus.Pass)
                return base.LintResult(base.LintStatus.Error)
            else:
                return base.LintResult(base.LintStatus.Error)
        except ValueError as e:
            return base.LintResult(base.LintStatus.Error)


def init():
    base.RegisterLint(base.Lint("e_ca_subject_field_empty","CA Certificates subject field MUST not be empty and MUST have a non-empty distingushed name","RFC 5280: 4.1.2.6",base.LintSource.RFC5280,Time.RFC2459Date,caSubjectEmpty()))