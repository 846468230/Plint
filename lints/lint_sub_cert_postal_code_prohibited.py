from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
'''
class subCertPostalCodeMustNotAppear(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            subject = c.subject
            if not subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) and not subject.get_attributes_for_oid(NameOID.GIVEN_NAME) and not subject.get_attributes_for_oid(NameOID.SURNAME):
                if subject.get_attributes_for_oid(NameOID.POSTAL_CODE):
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_postal_code_must_not_appear","Subscriber Certificate: subject:postalCode MUST NOT appear if the subject:organizationName field, subject:givenName field, or subject:surname fields are absent.","BRs: 7.1.4.2.2",base.LintSource.CABFBaselineRequirements,Time.CABGivenNameDate,subCertPostalCodeMustNotAppear()))