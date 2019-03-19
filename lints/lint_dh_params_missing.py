from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid
from cryptography.hazmat.primitives.asymmetric import dsa

class dsaParamsMissing(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return isinstance(c.public_key(),dsa.DSAPublicKey)
    
    def Execute(self,c):
        try:
            key = c.public_key()
            if key.public_numbers().parameter_numbers.p == 0 or key.public_numbers().parameter_numbers.q == 0 or key.public_numbers().parameter_numbers.g == 0:
                return  base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_dsa_params_missing","DSA: Certificates MUST include all domain parameters","BRs: 6.1.6",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,dsaParamsMissing()))