from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
'''
class IssuerDNTrailingSpace(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            AttibuteNames = c.issuer
            for ans in AttibuteNames: 
                if ans.value[-1]==" ":
                    return base.LintResult(base.LintStatus.Warn)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_issuer_dn_trailing_whitespace","AttributeValue in issuer RelativeDistinguishedName sequence SHOULD NOT have trailing whitespace","AWSLabs certlint",base.LintSource.AWSLabs,Time.ZeroDate,IssuerDNTrailingSpace()))