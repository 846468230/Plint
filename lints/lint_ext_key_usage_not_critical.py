from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
"When present, conforming CAs SHOULD mark this extension as critical."
'''
class checkKeyUsageCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.KEY_USAGE)

    def Execute(self,c):
        try:
            keyusage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            if keyusage.critical:
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Warn)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
        
def init():
    base.RegisterLint(base.Lint("w_ext_key_usage_not_critical","The keyUsage extension SHOULD be critical","RFC 5280: 4.2.1.3",base.LintSource.RFC5280,Time.RFC2459Date,checkKeyUsageCritical()))