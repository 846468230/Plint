from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.2.1.3
Conforming CAs MUST include this extension in certificates that
   contain public keys that are used to validate digital signatures on
   other public key certificates or CRLs.  When present, conforming CAs
   SHOULD mark this extension as critical.
'''
class caKeyUsageMissing(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsCACert(c)
    
    def Execute(self,c):
        try:
            c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return base.LintResult(base.LintStatus.Error)


def init():
    base.RegisterLint(base.Lint("e_ca_key_usage_missing","Root and Subordinate CA certificate keyUsage extension MUST be present","BRs: 7.1.2.1, RFC 5280: 4.2.1.3",base.LintSource.CABFBaselineRequirements,Time.RFC3280Date,caKeyUsageMissing()))