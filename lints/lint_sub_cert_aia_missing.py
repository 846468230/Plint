from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.3
authorityInformationAccess
With the exception of stapling, which is noted below, this extension MUST be present. It MUST NOT be
marked critical, and it MUST contain the HTTP URL of the Issuing CA’s OCSP responder (accessMethod
= 1.3.6.1.5.5.7.48.1). It SHOULD also contain the HTTP URL of the Issuing CA’s certificate
(accessMethod = 1.3.6.1.5.5.7.48.2). See Section 13.2.1 for details.
'''
class subCertAiaMissing(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) 

    def Execute(self,c):
        try:
            aias = c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)       
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_aia_missing","Subscriber Certiifcate: authorityInformationAccess MUST be present, with the exception of stapling.","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCertAiaMissing()))