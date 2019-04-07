from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
'''
class SubjectRDNHasMultipleAttribute(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            for subject in c.subject:
                if len(c.subject.get_attributes_for_oid(subject.oid))>1:
                    return base.LintResult(base.LintStatus.Notice)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("n_multiple_subject_rdn","Certificates typically do not have have multiple attributes in a single RDN (subject). This may be an error.","AWSLabs certlint",base.LintSource.AWSLabs,Time.ZeroDate,SubjectRDNHasMultipleAttribute()))