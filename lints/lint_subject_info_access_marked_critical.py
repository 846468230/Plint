from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
The subject information access extension indicates how to access information and services for the subject of the certificate in which the extension appears. When the subject is a CA, information and services may include certificate validation services and CA policy data. When the subject is an end entity, the information describes the type of services offered and how to access them. In this case, the contents of this extension are defined in the protocol specifications for the supported services. This extension may be included in end entity or CA certificates. Conforming CAs MUST mark this extension as non-critical.
'''
class siaCrit(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_INFORMATION_ACCESS)

    def Execute(self,c):
        try:
            subjectInformationAccess = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_INFORMATION_ACCESS)
            if subjectInformationAccess.critical:
                return base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_subject_info_access_marked_critical","Conforming CAs MUST mark the Subject Info Access extension as non-critical","RFC 5280: 4.2.2.2",base.LintSource.RFC5280,Time.RFC3280Date,siaCrit()))