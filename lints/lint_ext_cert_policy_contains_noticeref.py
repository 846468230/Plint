from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta
'''
The user notice has two optional fields: the noticeRef field and the
explicitText field. Conforming CAs SHOULD NOT use the noticeRef
option.
'''

class noticeRefPres(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.CERTIFICATE_POLICIES)
    
    def Execute(self,c):
        try:
            certpolicies = c.extensions.get_extension_for_class(x509.CertificatePolicies).value
            for certpolicy in certpolicies:
                if isinstance(certpolicy.policy_qualifiers,x509.UserNotice):
                    if certpolicy.policy_qualifiers.notice_reference:
                        return base.LintResult(base.LintStatus.Warn)  
            return  base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if str(e) =="The <ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)> extension is invalid and can't be parsed":
                return base.LintResult(base.LintStatus.Warn)
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("w_ext_cert_policy_contains_noticeref","Compliant certificates SHOULD NOT use the noticeRef option","RFC 5280: 4.2.1.4",base.LintSource.RFC5280,Time.RFC5280Date,noticeRefPres()))