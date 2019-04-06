from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID
from util.time import Time
from util import ca
'''
RFC 5280: A.1
	* In this Appendix, there is a list of upperbounds
	for fields in a x509 Certificate. *
	ub-common-name INTEGER ::= 64
'''
class subjectCommonNameMaxLength(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            subject = c.subject
            for commonName in subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                if len(commonName.value) > 64 :
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_subject_common_name_max_length","The commonName field of the subject MUST be less than 64 characters","RFC 5280: A.1",base.LintSource.RFC5280,Time.RFC2459Date,subjectCommonNameMaxLength()))