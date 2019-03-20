from lints import base
from cryptography import x509
from util.time import Time
from util import ca
from cryptography.hazmat.primitives.asymmetric import ec
class ecImproperCurves(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return isinstance(c.public_key(),ec.EllipticCurvePublicKey)
    
    def Execute(self,c):
        try:
            eckey = c.public_key()
            name = eckey.curve.name
            if name in ("secp256r1","secp384r1","secp521r1") :
                return base.LintResult(base.LintStatus.Pass)
            else:
                return base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.NA)
            


def init():
    base.RegisterLint(base.Lint("e_ec_improper_curves","Only one of NIST P‐256, P‐384, or P‐521 can be used","BRs: 6.1.5",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,ecImproperCurves()))