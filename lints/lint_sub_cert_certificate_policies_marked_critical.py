from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.3
certificatePolicies
This extension MUST be present and SHOULD NOT be marked critical.
'''
class subCertPolicyCrit(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and ca.IsExtInCert(c,ExtensionOID.CERTIFICATE_POLICIES)

    def Execute(self,c):
        try:
            certificatePolicies = c.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            if certificatePolicies.critical:
                    return base.LintResult(base.LintStatus.Warn)
            else:
                return  base.LintResult(base.LintStatus.Pass) 
       
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("w_sub_cert_certificate_policies_marked_critical","Subscriber Certificate: certificatePolicies MUST be present and SHOULD NOT be marked critical.","BRs: 7.1.2.3",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCertPolicyCrit()))