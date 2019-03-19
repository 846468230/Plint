from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
"""
RFC 5280: 4.2.1.9
Conforming CAs MUST include this extension in all CA certificates that contain
public keys used to validate digital signatures on certificates and MUST mark
the extension as critical in such certificates.  This extension MAY appear as a
critical or non- critical extension in CA certificates that contain public keys
used exclusively for purposes other than validating digital signatures on
certificates.  Such CA certificates include ones that contain public keys used
exclusively for validating digital signatures on CRLs and ones that contain key
management public keys used with certificate.
"""
class basicConstCrit(base.LintInterface):
    
    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsCACert(c) and ca.IsExtInCert(c,ExtensionOID.BASIC_CONSTRAINTS)
    
    def Execute(self,c):
        try:
            basic_constraint=c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS) 
        except:
            return  base.LintResult(base.LintStatus.NA)
        if basic_constraint.critical:
            return base.LintResult(base.LintStatus.Pass)
        else:
            return base.LintResult(base.LintStatus.Error)

def init():
    base.RegisterLint(base.Lint("e_basic_constraints_not_critical","basicConstraints MUST appear as a critical extension","RFC 5280: 4.2.1.9",base.LintSource.RFC5280,Time.RFC2459Date,basicConstCrit()))