from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
import idna
'''
'''
class IDNMalformedUnicode(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            SANs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            for SAN in SANs: 
                if isinstance(SAN,x509.DNSName):
                    for item in SAN.value.split('.'):
                        if "xn--" in item:
                            try:
                                idna.decode(item)
                            except UnicodeError:
                                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_international_dns_name_not_unicode","Internationalized DNSNames punycode not valid unicode","RFC 3490",base.LintSource.RFC5280,Time.RFC3490Date,IDNMalformedUnicode()))