from lints import base
from cryptography import x509
from util.time import Time
'''
RFC 5280: 4.1.2.2.  Serial Number
   The serial number MUST be a positive integer assigned by the CA to each
   certificate. It MUST be unique for each certificate issued by a given CA
   (i.e., the issuer name and serial number identify a unique certificate).
   CAs MUST force the serialNumber to be a non-negative integer.

   Given the uniqueness requirements above, serial numbers can be expected to
   contain long integers.  Certificate users MUST be able to handle serialNumber
   values up to 20 octets.  Conforming CAs MUST NOT use serialNumber values longer
   than 20 octets.

   Note: Non-conforming CAs may issue certificates with serial numbers that are
   negative or zero.  Certificate users SHOULD be prepared togracefully handle
   such certificates.
'''
class SerialNumberNotPositive(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return True

    def Execute(self,c):
        try:
            SerialNumber = c.serial_number
            if SerialNumber < 0:
                return base.LintResult(base.LintStatus.Error)
            else:
                return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return base.LintResult(base.LintStatus.Fatal)


def init():
    base.RegisterLint(base.Lint("e_serial_number_not_positive","Certificates must have a positive serial number","RFC 5280: 4.1.2.2",base.LintSource.RFC5280,Time.RFC3280Date,SerialNumberNotPositive()))