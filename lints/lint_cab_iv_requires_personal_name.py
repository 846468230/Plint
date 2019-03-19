from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid
'''
If the Certificate asserts the policy identifier of 2.23.140.1.2.3, then it MUST also include (i) either organizationName or givenName and surname, (ii) localityName (to the extent such field is required under Section 7.1.4.2.2), (iii) stateOrProvinceName (to the extent required under Section 7.1.4.2.2), and (iv) countryName in the Subject field.
'''
class CertPolicyRequiresPersonalName(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return oid.SliceContainsOID(c,oid.BRIndividualValidatedOID) and not ca.IsCACert(c)
    
    def Execute(self,c):
        try:
            if oid.TypeInName(c.subject,oid.OrganizationNameOID) or (oid.TypeInName(c.subject,oid.GivenNameOID) and oid.TypeInName(c.subject,oid.SurnameOID)):
                return  base.LintResult(base.LintStatus.Pass)
            else:
                return  base.LintResult(base.LintStatus.Error)
        except:
            return  base.LintResult(base.LintStatus.Pass)
            


def init():
    base.RegisterLint(base.Lint("e_cab_iv_requires_personal_name","If certificate policy 2.23.140.1.2.3 is included, either organizationName or givenName and surname MUST be included in subject","BRs: 7.1.6.1",base.LintSource.CABFBaselineRequirements,Time.CABV131Date,CertPolicyRequiresPersonalName()))