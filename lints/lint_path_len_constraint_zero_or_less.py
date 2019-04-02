from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
The pathLenConstraint field is meaningful only if the cA boolean is
asserted and the key usage extension, if present, asserts the
keyCertSign bit (Section 4.2.1.3).  In this case, it gives the
maximum number of non-self-issued intermediate certificates that may
follow this certificate in a valid certification path.  (Note: The
last certificate in the certification path is not an intermediate
certificate, and is not included in this limit.  Usually, the last
certificate is an end entity certificate, but it can be a CA
certificate.)  A pathLenConstraint of zero indicates that no non-
self-issued intermediate CA certificates may follow in a valid
certification path.  Where it appears, the pathLenConstraint field
MUST be greater than or equal to zero.  Where pathLenConstraint does
not appear, no limit is imposed.
'''
class pathLenNonPositive(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        try:
            basicConstrains = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            return True
        except x509.ExtensionNotFound:
            return False
        except ValueError:
            return True


    def Execute(self,c):
        try:
            basicConstrains = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if basicConstrains.path_length:
                if basicConstrains.path_length < 0:
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError as e:
            if "path_length" in str(e):
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_path_len_constraint_zero_or_less","Where it appears, the pathLenConstraint field MUST be greater than or equal to zero","RFC 5280: 4.2.1.9",base.LintSource.RFC5280,Time.RFC2459Date,pathLenNonPositive()))