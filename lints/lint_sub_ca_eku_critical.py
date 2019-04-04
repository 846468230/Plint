from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
BRs: 7.1.2.2g extkeyUsage (optional)
For Subordinate CA Certificates to be Technically constrained in line with section 7.1.5, then either the value
id‐kp‐serverAuth [RFC5280] or id‐kp‐clientAuth [RFC5280] or both values MUST be present**.
Other values MAY be present.
If present, this extension SHOULD be marked non‐critical.
'''
class subCAEKUCrit(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubCA(c) and ca.IsExtInCert(c,ExtensionOID.EXTENDED_KEY_USAGE)

    def Execute(self,c):
        try:
            extendKeyUsage = c.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            if extendKeyUsage.critical:
                return base.LintResult(base.LintStatus.Warn)
            else:
                return  base.LintResult(base.LintStatus.Pass) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("w_sub_ca_eku_critical","Subordinate CA certificate extkeyUsage extension should be marked non-critical if present","BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABV116Date,subCAEKUCrit()))