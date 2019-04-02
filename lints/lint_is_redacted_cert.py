from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,NameOID
from util.time import Time
from util import ca,fqdn
'''
Certificates MUST be of type X.509 v3.
'''
class DNSNameRedacted(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c)

    def Execute(self,c):
        try:
            common_names = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            for cn in common_names:
                if fqdn.isRedactedCertificate(cn):
                    return  base.LintResult(base.LintStatus.Notice)
            try:
                SANs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                for SAN in SANs: 
                    if isinstance(SAN,x509.DNSName):
                        if fqdn.isRedactedCertificate(SAN):
                            return  base.LintResult(base.LintStatus.Notice) 
            except x509.ExtensionNotFound:
                pass
            return  base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("n_contains_redacted_dnsname","Some precerts are redacted and of the form ?.?.a.com or *.?.a.com","IETF Draft: https://tools.ietf.org/id/draft-strad-trans-redaction-00.html",base.LintSource.ZLint,Time.CABV130Date,DNSNameRedacted()))