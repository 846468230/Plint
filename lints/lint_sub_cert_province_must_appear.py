from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
'''
class subCertProvinceMustAppear(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            subject = c.subject
            if subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or subject.get_attributes_for_oid(NameOID.GIVEN_NAME) or subject.get_attributes_for_oid(NameOID.SURNAME):
                if not subject.get_attributes_for_oid(NameOID.LOCALITY_NAME):
                    if not subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME):
                        return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_province_must_appear","Subscriber Certificate: subject:stateOrProvinceName MUST appear if the subject:organizationName, subject:givenName, or subject:surname fields are present and subject:localityName is absent.","BRs: 7.1.4.2.2",base.LintSource.CABFBaselineRequirements,Time.CABGivenNameDate,subCertProvinceMustAppear()))