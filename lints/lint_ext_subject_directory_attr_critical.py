from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.2.1.8
The subject directory attributes extension is used to convey
   identification attributes (e.g., nationality) of the subject.  The
   extension is defined as a sequence of one or more attributes.
   Conforming CAs MUST mark this extension as non-critical.
'''
class subDirAttrCrit(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES)

    def Execute(self,c):
        try:
            SDCs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES)
            if SDCs.critical:
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_subject_directory_attr_critical","Conforming CAs MUST mark the Subject Directory Attributes extension as not critical","RFC 5280: 4.2.1.8",base.LintSource.RFC5280,Time.RFC2459Date,subDirAttrCrit()))