from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
RFC 5280: 4.1.2.4
The issuer field identifies the entity that has signed and issued the
   certificate.  The issuer field MUST contain a non-empty distinguished
   name (DN).  The issuer field is defined as the X.501 type Name
   [X.501].
'''
class issuerFieldEmpty(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            AttibuteNames = c.issuer
            if not AttibuteNames:
                return base.LintResult(base.LintStatus.Error)
            for ans in AttibuteNames: 
                if ans.value:
                    return base.LintResult(base.LintStatus.Pass)
            return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_issuer_field_empty","Certificate issuer field MUST NOT be empty and must have a non-empty distingushed name","RFC 5280: 4.1.2.4",base.LintSource.RFC5280,Time.RFC2459Date,issuerFieldEmpty()))