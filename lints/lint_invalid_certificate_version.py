from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
Certificates MUST be of type X.509 v3.
'''
class InvalidCertificateVersion(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            if c.version != x509.Version.v3:
                return  base.LintResult(base.LintStatus.Error)
            else:
                return  base.LintResult(base.LintStatus.Pass)
        except x509.InvalidVersion:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_invalid_certificate_version","Certificates MUST be of type X.590 v3","BRs: 7.1.1",base.LintSource.CABFBaselineRequirements,Time.CABV130Date,InvalidCertificateVersion()))