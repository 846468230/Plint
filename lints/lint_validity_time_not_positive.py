from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
'''
class validityNegative(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            not_before = c.not_valid_before
            not_after = c.not_valid_after
            if not_before > not_after:
                return base.LintResult(base.LintStatus.Error)
            else:
                return base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if "time" in str(e):
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_validity_time_not_positive","Certificates MUST have a positive time for which they are valid","AWSLabs certlint",base.LintSource.AWSLabs,Time.ZeroDate,validityNegative()))