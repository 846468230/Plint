from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
The name MUST include both a
scheme (e.g., "http" or "ftp") and a scheme-specific-part.
'''
class IANURIFormat(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.ISSUER_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            names = c.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME).value
            for name in names:
                if isinstance(name,x509.UniformResourceIdentifier):
                    try:
                        uilparsed=urlparse(name.value)
                        if not uilparsed.scheme:
                            return base.LintResult(base.LintStatus.Error)
                        if not uilparsed.netloc and not uilparsed.path:
                            return base.LintResult(base.LintStatus.Error)
                    except ValueError:
                        return base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("e_ext_ian_uri_format_invalid","URIs in the subjectAltName extension MUST have a scheme and scheme specific part","RFC5280: 4.2.1.6",base.LintSource.RFC5280,Time.RFC5280Date,IANURIFormat()))