from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
'''
class SubCANameConstraintsNotCritical(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubCA(c) and ca.IsExtInCert(c,ExtensionOID.NAME_CONSTRAINTS)

    def Execute(self,c):
        try:
            NameConstraints = c.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
            if NameConstraints.critical:
                return base.LintResult(base.LintStatus.Pass)
            else:
                return  base.LintResult(base.LintStatus.Warn) 
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("w_sub_ca_name_constraints_not_critical","Subordinate CA Certificate: NameConstraints if present, SHOULD be marked critical.","BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABV102Date,SubCANameConstraintsNotCritical()))