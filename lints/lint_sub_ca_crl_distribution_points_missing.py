from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.2b cRLDistributionPoints
This extension MUST be present and MUST NOT be marked critical.
It MUST contain the HTTP URL of the CA’s CRL service.
'''
class subCACRLDistMissing(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubCA(c)

    def Execute(self,c):
        try:
            CRLDistributionPoints = c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            return  base.LintResult(base.LintStatus.Pass) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_ca_crl_distribution_points_missing","Subordinate CA Certificate: cRLDistributionPoints MUST be present and MUST NOT be marked critical.","BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCACRLDistMissing()))