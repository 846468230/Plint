from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta

class evValidTooLong(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        try:
            return ev.IsEV(c.extensions) and ca.IsSubscriberCert(c)
        except ValueError:
            return True
            
    def Execute(self,c):
        try:
            if c.not_valid_before + timedelta(days = 825) < c.not_valid_after:
                return  base.LintResult(base.LintStatus.Error)

            return  base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ev_valid_time_too_long","EV certificates must be 825 days in validity or less","BRs: 6.3.2",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,evValidTooLong()))