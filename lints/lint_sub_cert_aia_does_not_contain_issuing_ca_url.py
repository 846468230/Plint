from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.3
cRLDistributionPoints
This extension MAY be present. If present, it MUST NOT be marked critical, and it MUST contain the
HTTP URL of the CA’s CRL service. See Section 13.2.1 for details.
'''
class subCertIssuerUrl(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            aias = c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for ais in aias:
                if ais.access_method == AuthorityInformationAccessOID.CA_ISSUERS and ais.access_location.value.lower().startswith("http://"):
                    return base.LintResult(base.LintStatus.Pass)
            return  base.LintResult(base.LintStatus.Warn) 
       
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Warn)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("w_sub_cert_aia_does_not_contain_issuing_ca_url","Subscriber certificates authorityInformationAccess extension should contain the HTTP URL of the issuing CA’s certificate","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCertIssuerUrl()))