from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
When the issuerAltName extension contains a URI, the name MUST be
stored in the uniformResourceIdentifier (an IA5String).  The name
MUST NOT be a relative URI, and it MUST follow the URI syntax and
encoding rules specified in [RFC3986].  The name MUST include both a
scheme (e.g., "http" or "ftp") and a scheme-specific-part.  URIs that
include an authority ([RFC3986], Section 3.2) MUST include a fully
qualified domain name or IP address as the host.  Rules for encoding
Internationalized Resource Identifiers (IRIs) are specified in
Section 7.4.
'''
class uriRelative(base.LintInterface):

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
                    except ValueError:
                        return base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("e_ext_ian_uri_relative","When issuerAltName extension is present and the URI is used, the name MUST NOT be a relative URI","RFC 5280: 4.2.1.7",base.LintSource.RFC5280,Time.RFC5280Date,uriRelative()))