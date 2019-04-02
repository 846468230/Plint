from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
BRs: 7.1.2.1c certificatePolicies
This extension SHOULD NOT be present.
'''
class rootCAContainsCertPolicy(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsRootCA(c)

    def Execute(self,c):
        try:
            certPolicy = c.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            return base.LintResult(base.LintStatus.Warn)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_root_ca_contains_cert_policy","Root CA Certificate: certificatePolicies SHOULD NOT be present.","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,rootCAContainsCertPolicy()))