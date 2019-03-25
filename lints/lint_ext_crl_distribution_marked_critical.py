from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
The CRL distribution points extension identifies how CRL information is obtained. The extension SHOULD be non-critical, but this profile RECOMMENDS support for this extension by CAs and applications.
'''
class ExtCrlDistributionMarkedCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.CRL_DISTRIBUTION_POINTS)

    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).critical:
                return  base.LintResult(base.LintStatus.Warn) 
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_ext_crl_distribution_marked_critical","If included, the CRL Distribution Points extension SHOULD NOT be marked critical","RFC 5280: 4.2.1.13",base.LintSource.RFC5280,Time.RFC2459Date,ExtCrlDistributionMarkedCritical()))