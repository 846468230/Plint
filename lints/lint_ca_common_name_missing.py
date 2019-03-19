from lints import base
from util import ca
from cryptography.x509.oid import NameOID
from util.time import Time

class caCommonNameMissing(base.LintInterface):
    
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsCACert(c)

    def Execute(self,c):
        if len(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)):
            return base.LintResult(base.LintStatus.Pass)
        else:
            return base.LintResult(base.LintStatus.Error)


def init():
    base.RegisterLint(base.Lint("e_ca_common_name_missing","CA Certificates common name MUST be included.","BRs: 7.1.4.3.1",base.LintSource.CABFBaselineRequirements,Time.CABV148Date,caCommonNameMissing()))