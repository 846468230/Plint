from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
'''
class pathLenIncluded(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.BASIC_CONSTRAINTS)


    def Execute(self,c):
        try:
            basicConstrains = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if basicConstrains.path_length:
                if not basicConstrains.ca:
                    return base.LintResult(base.LintStatus.Error)
                try:
                    keyUsage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                    if not keyUsage.key_cert_sign:
                        return base.LintResult(base.LintStatus.Error)
                except x509.ExtensionNotFound:
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError as e:
            if "path_length" in str(e):
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_path_len_constraint_improperly_included","CAs MUST NOT include the pathLenConstraint field unless the CA boolean is asserted and the keyCertSign bit is set","RFC 5280: 4.2.1.9",base.LintSource.RFC5280,Time.RFC3280Date,pathLenIncluded()))