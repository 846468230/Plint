from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
BRs: 7.1.4.2.2
Required/Optional: Deprecated (Discouraged, but not prohibited)
'''
class commonNames(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            subject = c.subject
            if not subject.get_attributes_for_oid(NameOID.COMMON_NAME) :
                    return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Notice)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("n_subject_common_name_included","Subscriber Certificate: commonName is deprecated.","BRs: 7.1.4.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,commonNames()))