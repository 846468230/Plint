from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid
'''
'''
class subCertSubjectGnOrSnContainsPolicy(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        if ca.IsSubscriberCert(c):
            subject = c.subject
            if subject.get_attributes_for_oid(NameOID.GIVEN_NAME) or subject.get_attributes_for_oid(NameOID.SURNAME):
                return True
        return False

    def Execute(self,c):
        try:
            CertificatePolicies = c.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
            for PolicyInformation in CertificatePolicies:
                if PolicyInformation.policy_identifier == oid.BRIndividualValidatedOID :
                    return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Error)
        except x509.ExtensionNotFound:
            return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_given_name_surname_contains_correct_policy","Subscriber Certificate: A certificate containing a subject:givenName field or subject:surname field MUST contain the (2.23.140.1.2.3) certPolicy OID.","BRs: 7.1.4.2.2",base.LintSource.CABFBaselineRequirements,Time.CABGivenNameDate,subCertSubjectGnOrSnContainsPolicy()))