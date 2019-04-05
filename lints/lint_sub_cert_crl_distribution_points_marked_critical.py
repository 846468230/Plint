from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.3
cRLDistributionPoints
This extension MAY be present. If present, it MUST NOT be marked critical, and it MUST contain the HTTP
URL of the CA’s CRL service.
'''
class subCrlDistCrit(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and ca.IsExtInCert(c,ExtensionOID.CRL_DISTRIBUTION_POINTS)

    def Execute(self,c):
        try:
            CRLDistributionPoints = c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            if CRLDistributionPoints.critical:
                return base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_crl_distribution_points_marked_critical","Subscriber Certiifcate: cRLDistributionPoints MUST NOT be marked critical, and MUST contain the HTTP URL of the CA's CRL service.","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCrlDistCrit()))