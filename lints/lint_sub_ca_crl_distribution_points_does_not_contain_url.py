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
class subCACRLDistNoUrl(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubCA(c) and ca.IsExtInCert(c,ExtensionOID.CRL_DISTRIBUTION_POINTS)

    def Execute(self,c):
        try:
            
            CRLDistributionPoints = c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            for CRLDistributionPoint in CRLDistributionPoints:
                for GeneralName in CRLDistributionPoint.full_name:
                    if isinstance(GeneralName,x509.UniformResourceIdentifier):
                        if GeneralName.value.startswith("http://"):
                            return base.LintResult(base.LintStatus.Pass)
            return  base.LintResult(base.LintStatus.Error) 
       
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_ca_crl_distribution_points_does_not_contain_url","Subordinate CA Certificate: cRLDistributionPoints MUST contain the HTTP URL of the CA's CRL service.","BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCACRLDistNoUrl()))