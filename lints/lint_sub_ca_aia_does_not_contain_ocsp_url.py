from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
CAB 7.1.2.2c
With the exception of stapling, which is noted below, this extension MUST be present. It MUST NOT be
marked critical, and it MUST contain the HTTP URL of the Issuing CA’s OCSP responder (accessMethod
= 1.3.6.1.5.5.7.48.1). It SHOULD also contain the HTTP URL of the Issuing CA’s certificate
(accessMethod = 1.3.6.1.5.5.7.48.2).
'''
class subCaOcspUrl(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsCACert(c) and not ca.IsRootCA(c)

    def Execute(self,c):
        try:
            aias = c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for ais in aias:
                if ais.access_method == AuthorityInformationAccessOID.OCSP and ais.access_location.value.lower().startswith("http://"):
                    return base.LintResult(base.LintStatus.Pass)
            return  base.LintResult(base.LintStatus.Error) 
       
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_ca_aia_does_not_contain_ocsp_url","Subordinate CA certificates authorityInformationAccess extension must contain the HTTP URL of the issuing CA’s OCSP responder","BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCaOcspUrl()))