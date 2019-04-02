from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import rsa
'''
7.1.2.1. Root CA Certificate
a. basicConstraints
This extension MUST appear as a critical extension. The cA field MUST be set true. The pathLenConstraint field SHOULD NOT be present.
'''
class rootCaPathLenPresent(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsRootCA(c) and ca.IsExtInCert(c,ExtensionOID.BASIC_CONSTRAINTS)


    def Execute(self,c):
        try:
            basicConstrains = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if basicConstrains.path_length:
                return base.LintResult(base.LintStatus.Warn)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError as e:
            #if "path_length" in str(e):
            #    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("w_root_ca_basic_constraints_path_len_constraint_field_present","Root CA certificate basicConstraint extension pathLenConstraint field SHOULD NOT be present","BRs: 7.1.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,rootCaPathLenPresent()))