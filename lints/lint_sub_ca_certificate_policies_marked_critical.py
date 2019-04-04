from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.2a certificatePolicies
This extension MUST be present and SHOULD NOT be marked critical.
'''
class subCACertPolicyCrit(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubCA(c) and ca.IsExtInCert(c,ExtensionOID.CERTIFICATE_POLICIES)

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
    base.RegisterLint(base.Lint("w_sub_ca_certificate_policies_marked_critical","Subordinate CA certificates certificatePolicies extension should not be marked as critical","BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCACertPolicyCrit()))