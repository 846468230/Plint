from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time,addMonths
from util import ca
'''
'''
class subCertValidTimeLongerThan39Months(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            if addMonths(c.not_valid_before,39) < c.not_valid_after:
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_valid_time_longer_than_39_months","Subscriber Certificates issued after 1 July 2016 but prior to 1 March 2018 MUST have a Validity Period no greater than 39 months.","BRs: 6.3.2",base.LintSource.CABFBaselineRequirements,Time.SubCert39Month,subCertValidTimeLongerThan39Months()))