from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,AuthorityInformationAccessOID
from util.time import Time
from util import ca
'''
RFC 5280: 4.2.2.1
An authorityInfoAccess extension may include multiple instances of
   the id-ad-caIssuers accessMethod.  The different instances may
   specify different methods for accessing the same information or may
   point to different information.  When the id-ad-caIssuers
   accessMethod is used, at least one instance SHOULD specify an
   accessLocation that is an HTTP [RFC2616] or LDAP [RFC4516] URI.
'''
class aiaNoHTTPorLDAP(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        try:
            if ca.IsExtInCert(c,ExtensionOID.AUTHORITY_INFORMATION_ACCESS):
                aias = c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
                for ais in aias:
                    if ais.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                        return True                
            return False
        except x509.ExtensionNotFound:
            return False
        except ValueError:
            return True

    def Execute(self,c):
        try:
            aias = c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for ais in aias:
                if ais.access_method == AuthorityInformationAccessOID.CA_ISSUERS and (ais.access_location.value.lower().startswith("http://") or ais.access_location.value.lower().startswith("ldap://")):
                    return base.LintResult(base.LintStatus.Pass)
            return  base.LintResult(base.LintStatus.Warn) 
       
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("w_ext_aia_access_location_missing","When the id-ad-caIssuers accessMethod is used, at least one instance SHOULD specify an accessLocation that is an HTTP or LDAP URI","RFC 5280: 4.2.2.1",base.LintSource.RFC5280,Time.RFC5280Date,aiaNoHTTPorLDAP()))