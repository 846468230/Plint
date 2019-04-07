from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
ITU-T X.520 (02/2001) UpperBounds
ub-street-address INTEGER ::= 128
'''
class subjectStreetAddressMaxLength(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return c.subject.get_attributes_for_oid(NameOID.STREET_ADDRESS)

    def Execute(self,c):
        try:
            subject = c.subject
            for Street in subject.get_attributes_for_oid(NameOID.STREET_ADDRESS):
                if len(Street.value) > 128 :
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_subject_street_address_max_length","The 'StreetAddress' field of the subject MUST be less than 129 characters","ITU-T X.520 (02/2001) UpperBounds",base.LintSource.RFC5280,Time.RFC2459Date,subjectStreetAddressMaxLength()))