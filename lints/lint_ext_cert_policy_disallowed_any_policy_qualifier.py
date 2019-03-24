from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta
'''
RFC 5280: 4.2.1.4
To promote interoperability, this profile RECOMMENDS that policy
information terms consist of only an OID.  Where an OID alone is
insufficient, this profile strongly recommends that the use of
qualifiers be limited to those identified in this section.  When
qualifiers are used with the special policy anyPolicy, they MUST be
limited to the qualifiers identified in this section.  Only those
qualifiers returned as a result of path validation are considered.
'''

class unrecommendedQualifier(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.CERTIFICATE_POLICIES)
    
    def Execute(self,c):
        try:
            certpolicies = c.extensions.get_extension_for_class(x509.CertificatePolicies).value
            for certpolicy in certpolicies:
                if not isinstance(certpolicy.policy_qualifiers,x509.UserNotice) and not isinstance(certpolicy.policy_qualifiers,str):
                    continue
            return  base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if str(e) =="The <ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)> extension is invalid and can't be parsed":
                return base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ext_cert_policy_disallowed_any_policy_qualifier","When qualifiers are used with the special policy anyPolicy, they must be limited to qualifiers identified in this section: (4.2.1.4)","RFC 5280: 4.2.1.4",base.LintSource.RFC5280,Time.RFC3280Date,unrecommendedQualifier()))