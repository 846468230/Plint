from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid
'''
If the Certificate asserts the policy identifier of 2.23.140.1.2.1, then it MUST NOT include
organizationName, streetAddress, localityName, stateOrProvinceName, or postalCode in the Subject field.
'''
class certPolicyConflictsWithLocality(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return oid.SliceContainsOID(c,oid.BRDomainValidatedOID) and not ca.IsCACert(c)
    
    def Execute(self,c):
        try:
            if oid.TypeInName(c.subject,oid.LocalityNameOID):
                return  base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except:
            return  base.LintResult(base.LintStatus.Error)
            


def init():
    base.RegisterLint(base.Lint("e_cab_dv_conflicts_with_locality","If certificate policy 2.23.140.1.2.1 (CA/B BR domain validated) is included, locality name MUST NOT be included in subject","BRs: 7.1.6.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,certPolicyConflictsWithLocality()))