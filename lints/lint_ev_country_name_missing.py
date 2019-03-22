from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid,ev


class evCountryMissing(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        try:
            return ev.IsEV(c.extensions) and ca.IsSubscriberCert(c)
        except ValueError:
            return True
            
    def Execute(self,c):
        try:
            if oid.TypeInName(c.subject,oid.CountryNameOID):
                return  base.LintResult(base.LintStatus.Pass)
            else:
                return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ev_country_name_missing","EV certificates must include countryName in subject","BRs: 7.1.6.1",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,evCountryMissing()))