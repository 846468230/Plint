from lints import base
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from util.time import Time
from util import ca,oid,ev
from datetime import timedelta
'''
An explicitText field includes the textual statement directly in
the certificate.  The explicitText field is a string with a
maximum size of 200 characters.  Conforming CAs SHOULD use the
UTF8String encoding for explicitText.  VisibleString or BMPString
are acceptable but less preferred alternatives.  Conforming CAs
MUST NOT encode explicitText as IA5String.  The explicitText string
SHOULD NOT include any control characters (e.g., U+0000 to U+001F
and U+007F to U+009F).  When the UTF8String or BMPString encoding
is used, all character sequences SHOULD be normalized according
to Unicode normalization form C (NFC) [NFC].
'''

class explicitTextTooLong(base.LintInterface):
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        try:
            if ca.IsExtInCert(c,ExtensionOID.CERTIFICATE_POLICIES):
                certpolicies = c.extensions.get_extension_for_class(x509.CertificatePolicies).value
                for certpolicy in certpolicies:
                    if not certpolicy.policy_qualifiers:
                        continue
                    for policy_qualifier in certpolicy.policy_qualifiers:
                        if isinstance(policy_qualifier,x509.UserNotice) and policy_qualifier.explicit_text:
                            return True
            return False
        except ValueError as e:
            if str(e) =="The <ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)> extension is invalid and can't be parsed":
                return True
            return False

    def Execute(self,c):
        try:
            certpolicies = c.extensions.get_extension_for_class(x509.CertificatePolicies).value
            for certpolicy in certpolicies:
                if not certpolicy.policy_qualifiers:
                        continue
                for  policy_qualifier in certpolicy.policy_qualifiers:
                    if isinstance(policy_qualifier,x509.UserNotice) and len(policy_qualifier.explicit_text.encode()) > 200:
                        return base.LintResult(base.LintStatus.Error)  
            return  base.LintResult(base.LintStatus.Pass)
        except ValueError as e:
            if str(e) =="The <ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)> extension is invalid and can't be parsed":
                return base.LintResult(base.LintStatus.Error)
            return  base.LintResult(base.LintStatus.Fatal)
            


def init():
    base.RegisterLint(base.Lint("e_ext_cert_policy_explicit_text_too_long","Explicit text has a maximum size of 200 characters","RFC 6818: 3",base.LintSource.RFC5280,Time.RFC6818Date,explicitTextTooLong()))