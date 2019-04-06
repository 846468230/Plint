from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
from datetime import timedelta
'''
'''
class subCertValidTimeLongerThan825Days(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            if c.not_valid_before + timedelta(days = 825) < c.not_valid_after:
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_valid_time_longer_than_825_days","Subscriber Certificates issued after 1 March 2018 MUST have a Validity Period no greater than 825 days.","BRs: 6.3.2",base.LintSource.CABFBaselineRequirements,Time.SubCert825Days,subCertValidTimeLongerThan825Days()))