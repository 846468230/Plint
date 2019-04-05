from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
'''
class subCertAiaMarkedCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and ca.IsExtInCert(c,ExtensionOID.AUTHORITY_INFORMATION_ACCESS)

    def Execute(self,c):
        try:
            aias = c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            if aias.critical:
                    return base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass) 
       
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_aia_marked_critical","Subscriber Certificate: authorityInformationAccess MUST NOT be marked critical","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCertAiaMarkedCritical()))