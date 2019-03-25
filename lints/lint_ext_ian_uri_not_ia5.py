from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
When the issuerAltName extension contains a URI, the name MUST be
stored in the uniformResourceIdentifier (an IA5String).
'''
class IANURIIA5String(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.ISSUER_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            names = c.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME).value
            return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except UnicodeDecodeError:
            return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("e_ext_ian_uri_not_ia5","When subjectAltName contains a URI, the name MUST be an IA5 string","RFC 5280: 4.2.1.7",base.LintSource.RFC5280,Time.RFC5280Date,IANURIIA5String()))