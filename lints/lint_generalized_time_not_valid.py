from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
 4.1.2.5.2.  GeneralizedTime
The generalized time type, GeneralizedTime, is a standard ASN.1 type
for variable precision representation of time.  Optionally, the
GeneralizedTime field can include a representation of the time
differential between local and Greenwich Mean Time.

For the purposes of this profile, GeneralizedTime values MUST be
expressed in Greenwich Mean Time (Zulu) and MUST include seconds
(i.e., times are YYYYMMDDHHMMSSZ), even where the number of seconds
is zero.  GeneralizedTime values MUST NOT include fractional seconds.
'''
class generalizedNotValid(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            not_before = c.not_valid_before
            not_after = c.not_valid_after
            return base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if "time" in str(e):
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_generalized_time_not_valid","Generalized time values MUST be expressed in Greenwich Mean Time (Zulu) and has second and no friction","RFC 5280: 4.1.2.5.2",base.LintSource.RFC5280,Time.RFC2459Date,generalizedNotValid()))