from lints import base
from cryptography import x509
from util.time import Time
from util import ca
from cryptography.hazmat.primitives import hashes
from datetime import datetime
'''
Effective 16 January 2015, CAs SHOULD NOT issue Subscriber Certificates utilizing the SHA‐1 algorithm with
an Expiry Date greater than 1 January 2017 because Application Software Providers are in the process of
deprecating and/or removing the SHA‐1 algorithm from their software, and they have communicated that
CAs and Subscribers using such certificates do so at their own risk.
'''
class sha1ExpireLong(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsSubscriberCert(c) and isinstance(c.signature_hash_algorithm,hashes.SHA1)

    def Execute(self,c):
        try:
            if  c.not_valid_after > datetime(2017,1,1,0,0,0,0) :
                return base.LintResult(base.LintStatus.Warn)
            else:
                return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)


def init():
    base.RegisterLint(base.Lint("w_sub_cert_sha1_expiration_too_long","Subscriber certificates using the SHA-1 algorithm SHOULD NOT have an expiration date later than 1 Jan 2017","BRs: 7.1.3",base.LintSource.CABFBaselineRequirements,datetime(2015,1,16,0,0,0,0),sha1ExpireLong()))