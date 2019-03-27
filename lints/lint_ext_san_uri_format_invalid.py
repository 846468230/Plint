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
class extSANURIFormatInvalid(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            SANs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            for SAN in SANs: 
                if isinstance(SAN,x509.UniformResourceIdentifier):
                    uri = urlparse(SAN.value)
                    if uri.scheme=="" :
                        return base.LintResult(base.LintStatus.Error)
                    if uri.netloc=='' and uri.path=='' and uri.params=='' and uri.query=='' and uri.fragment=='' :
                        return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_san_uri_format_invalid","URIs in SAN extension must have a scheme and scheme specific part","RFC 5280: 4.2.1.6",base.LintSource.RFC5280,Time.RFC5280Date,extSANURIFormatInvalid()))