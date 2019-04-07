from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.1.2.6
 Where it is non-empty, the subject field MUST contain an X.500
   distinguished name (DN). The DN MUST be unique for each subject
   entity certified by the one CA as defined by the issuer name field. A
   CA may issue more than one certificate with the same DN to the same
   subject entity.
'''
class subjectDN(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            c.subject
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Error)

def init():
    base.RegisterLint(base.Lint("e_subject_not_dn","When not empty, the subject field MUST be a distinguished name","RFC 5280: 4.1.2.6",base.LintSource.RFC5280,Time.RFC2459Date,subjectDN()))