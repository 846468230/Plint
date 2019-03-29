from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
'''
class brIANWildcardFirst(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.ISSUER_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            IANs = c.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME).value
            for IAN in IANs: 
                if isinstance(IAN,x509.DNSName):
                    if '*' in IAN.value[1:]:
                        return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ian_wildcard_not_first","A wildcard MUST be in the first label of FQDN (ie not: www.*.com) (Only checks DNSName)","awslabs certlint",base.LintSource.AWSLabs,Time.ZeroDate,brIANWildcardFirst()))