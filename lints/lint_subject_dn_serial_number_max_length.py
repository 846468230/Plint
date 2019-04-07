from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
'''
class SubjectDNSerialNumberMaxLength(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return c.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)

    def Execute(self,c):
        try:
            subject = c.subject
            for serialNumber in subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER):
                if len(serialNumber.value) > 64 :
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_subject_dn_serial_number_max_length","The 'Serial Number' field of the subject MUST be less than 64 characters","RFC 5280: Appendix A",base.LintSource.RFC5280,Time.ZeroDate,SubjectDNSerialNumberMaxLength()))