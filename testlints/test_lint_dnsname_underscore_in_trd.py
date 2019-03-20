import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_underscore_in_trd
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameUnderscoreInTRD(unittest.TestCase):
    '''test lint_dnsname_underscore_in_trd.py'''
    def test_DNSNameUnderscoreInTRD(self):
        certPath ='..\\testCerts\\dnsNameUnderscoreInTRD.pem'
        lint_dnsname_underscore_in_trd.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_dnsname_underscore_in_trd"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
        
    def test_DNSNameNoUnderscoreInTRD(self):
        certPath ='..\\testCerts\\dnsNameNoUnderscoreInTRD.pem'
        lint_dnsname_underscore_in_trd.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_dnsname_underscore_in_trd"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
