from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
BRs: 7.1.6.4
Subscriber Certificates
A Certificate issued to a Subscriber MUST contain one or more policy identifier(s), defined by the Issuing CA, in
the Certificate’s certificatePolicies extension that indicates adherence to and complIANce with these Requirements.
CAs complying with these Requirements MAY also assert one of the reserved policy OIDs in such Certificates.
'''
class subCertPolicyEmpty(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            certificatePolicies = c.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            if certificatePolicies.value:
                    return base.LintResult(base.LintStatus.Pass)
            else:
                return  base.LintResult(base.LintStatus.Error) 
       
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_sub_cert_cert_policy_empty","Subscriber certificates must contain at least one policy identifier that indicates adherence to CAB standards","BRs: 7.1.6.4",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,subCertPolicyEmpty()))