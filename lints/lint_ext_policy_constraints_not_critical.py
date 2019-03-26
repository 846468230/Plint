from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
RFC 5280: 4.2.1.11
Conforming CAs MUST mark this extension as critical.
'''
class policyConstraintsCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.POLICY_CONSTRAINTS)

    def Execute(self,c):
        try:
            pc = c.extensions.get_extension_for_oid(ExtensionOID.POLICY_CONSTRAINTS)
            if pc.critical:
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_policy_constraints_not_critical","Conforming CAs MUST mark the policy constraints extension as critical","RFC 5280: 4.2.1.11",base.LintSource.RFC5280,Time.RFC5280Date,policyConstraintsCritical()))