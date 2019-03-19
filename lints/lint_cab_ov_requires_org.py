from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid
'''
If the Certificate asserts the policy identifier of 2.23.140.1.2.2, then it MUST also include organizationName, localityName (to the extent such field is required under Section 7.1.4.2.2), stateOrProvinceName (to the extent such field is required under Section 7.1.4.2.2), and countryName in the Subject field.
'''
class CertPolicyRequiresOrg(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return oid.SliceContainsOID(c,oid.BROrganizationValidatedOID) and not ca.IsCACert(c)
    
    def Execute(self,c):
        try:
            if oid.TypeInName(c.subject,oid.OrganizationNameOID):
                return  base.LintResult(base.LintStatus.Pass)
            else:
                return  base.LintResult(base.LintStatus.Error)
        except:
            return  base.LintResult(base.LintStatus.Pass)
            


def init():
    base.RegisterLint(base.Lint("e_cab_ov_requires_org","If certificate policy 2.23.140.1.2.2 is included, organizationName MUST be included in subject","BRs: 7.1.6.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,CertPolicyRequiresOrg()))