from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
"""
RFC 5280: 4.2.1.13
When present, DistributionPointName SHOULD include at least one LDAP or HTTP URI.
"""
class distribNoLDAPorURI(base.LintInterface):
    
    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.CRL_DISTRIBUTION_POINTS)
    
    def Execute(self,c):
        try:
            distributions=c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            for distribution in distributions:
                for uri in distribution.full_name:
                    if "http://" in uri.value.lower() or "ldap://" in uri.value.lower():
                        return  base.LintResult(base.LintStatus.Pass)
            return  base.LintResult(base.LintStatus.Warn)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("w_distribution_point_missing_ldap_or_uri","When present in the CRLDistributionPoints extension, DistributionPointName SHOULD include at least one LDAP or HTTP URI","RFC 5280: 4.2.1.13",base.LintSource.RFC5280,Time.RFC5280Date,distribNoLDAPorURI()))