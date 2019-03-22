from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca,oid,ev


class evSNMissing(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        try:
            return ev.IsEV(c.extensions) and ca.IsSubscriberCert(c)
        except ValueError:
            return True
            
    def Execute(self,c):
        try:
            if len(c.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)) == 0:
                return  base.LintResult(base.LintStatus.Error)

            return  base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ev_serial_number_missing","EV certificates must include serialNumber in subject","EV gudelines: 9.2.6",base.LintSource.CABFBaselineRequirements,Time.ZeroDate,evSNMissing()))