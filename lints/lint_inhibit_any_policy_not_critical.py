from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
4.2.1.14.  Inhibit anyPolicy
   The inhibit anyPolicy extension can be used in certificates issued to CAs.
   The inhibit anyPolicy extension indicates that the special anyPolicy OID,
   with the value { 2 5 29 32 0 }, is not considered an explicit match for other
   certificate policies except when it appears in an intermediate self-issued
   CA certificate. The value indicates the number of additional non-self-issued
   certificates that may appear in the path before anyPolicy is no longer permitted.
   For example, a value of one indicates that anyPolicy may be processed in
   certificates issued by the subject of this certificate, but not in additional
   certificates in the path.

   Conforming CAs MUST mark this extension as critical.
'''
class InhibitAnyPolicyNotCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.INHIBIT_ANY_POLICY)

    def Execute(self,c):
        try:
            anyPolicy = c.extensions.get_extension_for_oid(ExtensionOID.INHIBIT_ANY_POLICY)
            if not anyPolicy.critical:
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_inhibit_any_policy_not_critical","CAs MUST mark the inhibitAnyPolicy extension as critical","RFC 5280: 4.2.1.14",base.LintSource.RFC5280,Time.RFC3280Date,InhibitAnyPolicyNotCritical()))