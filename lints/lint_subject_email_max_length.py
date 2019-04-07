from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
RFC 5280: A.1
	* In this Appendix, there is a list of upperbounds
	for fields in a x509 Certificate. *
	ub-emailaddress-length INTEGER ::= 128

The ASN.1 modules in Appendix A are unchanged from RFC 3280, except
that ub-emailaddress-length was changed from 128 to 255 in order to
align with PKCS #9 [RFC2985].

ub-emailaddress-length INTEGER ::= 255
'''
class subjectEmailMaxLength(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return c.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)

    def Execute(self,c):
        try:
            subject = c.subject
            for email in subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS):
                if len(email.value) > 255 :
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_subject_email_max_length","The 'Email' field of the subject MUST be less than 255 characters","RFC 5280: A.1",base.LintSource.RFC5280,Time.RFC2459Date,subjectEmailMaxLength()))