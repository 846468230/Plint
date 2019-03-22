from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta
'''
Authority Information Access
The authority information access extension indicates how to access information and services for the issuer of the certificate in which the extension appears. Information and services may include on-line validation services and CA policy data. (The location of CRLs is not specified in this extension; that information is provided by the cRLDistributionPoints extension.) This extension may be included in end entity or CA certificates. Conforming CAs MUST mark this extension as non-critical.
'''
#See also: BRs: 7.1.2.3 & CAB: 7.1.2.2
class ExtAiaMarkedCritical(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsExtInCert(c,oid.AiaOID)
    
    def Execute(self,c):
        try:
            if c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).critical:
                return  base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ext_aia_marked_critical","Conforming CAs must mark the Authority Information Access extension as non-critical","RFC 5280: 4.2.2.1",base.LintSource.RFC5280,Time.RFC2459Date,ExtAiaMarkedCritical()))