from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.1e
The Certificate Subject MUST contain the following: organizationName (OID 2.5.4.10): This field MUST be present and the contents MUST contain either the Subject CA’s name or DBA as verified under Section 3.2.2.2.
'''
class caOrganizationNameMissing(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsCACert(c)
    
    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)) and c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value :
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except ValueError as e:
            return base.LintResult(base.LintStatus.Error)


def init():
    base.RegisterLint(base.Lint("e_ca_organization_name_missing","Root and Subordinate CA certificates MUST have a organizationName present in subject information","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,caOrganizationNameMissing()))