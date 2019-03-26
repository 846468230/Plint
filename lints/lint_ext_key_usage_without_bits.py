from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
This profile does not restrict the combinations of bits that may be
   set in an instantiation of the keyUsage extension.  However,
   appropriate values for keyUsage extensions for particular algorithms
   are specified in [RFC3279], [RFC4055], and [RFC4491].  When the
   keyUsage extension appears in a certificate, at least one of the bits
   MUST be set to 1.
'''
class keyUsageBitsSet(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.KEY_USAGE)

    def Execute(self,c):
        try:
            keyusage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            bits = keyusage.value
            if not bits.digital_signature and not bits.content_commitment and not bits.key_encipherment and not bits.data_encipherment  and not bits.key_agreement and not bits.key_cert_sign and not bits.crl_sign :
                return base.LintResult(base.LintStatus.Error)
            else:
                return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("e_ext_key_usage_without_bits","When the keyUsage extension is included, at least one bit MUST be set to 1","RFC 5280: 4.2.1.3",base.LintSource.RFC5280,Time.RFC5280Date,keyUsageBitsSet()))