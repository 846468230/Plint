from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
"""
The cRLDistributionPoints extension is a SEQUENCE of
DistributionPoint.  A DistributionPoint consists of three fields,
each of which is optional: distributionPoint, reasons, and cRLIssuer.
While each of these fields is optional, a DistributionPoint MUST NOT
consist of only the reasons field; either distributionPoint or
cRLIssuer MUST be present.  If the certificate issuer is not the CRL
issuer, then the cRLIssuer field MUST be present and contain the Name
of the CRL issuer.  If the certificate issuer is also the CRL issuer,
then conforming CAs MUST omit the cRLIssuer field and MUST include
the distributionPoint field.
"""
class dpIncomplete(base.LintInterface):
    
    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.CRL_DISTRIBUTION_POINTS)
    
    def Execute(self,c):
        try:
            distributions=c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            for distribution in distributions:
                if distribution.reasons !=None and distribution.full_name == None and distribution.relative_name==None and distribution.crl_issuer==None:
                     return  base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Pass)
        except:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_distribution_point_incomplete","A DistributionPoint from the CRLDistributionPoints extension MUST NOT consist of only the reasons field; either distributionPoint or CRLIssuer must be present","RFC 5280: 4.2.1.13",base.LintSource.RFC5280,Time.RFC3280Date,dpIncomplete()))