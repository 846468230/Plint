from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
from urllib.parse import urlparse
'''
7.1.4.2.1. Subject Alternative Name Extension
Certificate Field: extensions:subjectAltName
Required/Optional:  Required
Contents:  This extension MUST contain at least one entry.  Each entry MUST be either a dNSName containing
the Fully‐Qualified Domain Name or an iPAddress containing the IP address of a server.  The CA MUST
confirm that the Applicant controls the Fully‐Qualified Domain Name or IP address or has been granted the
right to use it by the Domain Name Registrant or IP address assignee, as appropriate.
Wildcard FQDNs are permitted.
'''
class SANDirName(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    def Execute(self,c):
        try:
            SANs = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            for SAN in SANs: 
                if not isinstance(SAN,x509.DNSName) and not isinstance(SAN,x509.IPAddress):
                    return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError as e:
            if str(e)=="The <ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)> extension is invalid and can't be parsed":
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_ext_san_must_be_dns_or_ipaddress","The Subject Alternate Name extension MUST contain only 'dnsName' and 'ipaddress' name types","BRs: 7.1.4.2.1",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,SANDirName()))