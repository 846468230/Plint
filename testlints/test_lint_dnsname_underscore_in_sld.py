import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_underscore_in_sld
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameUnderscoreInSLD(unittest.TestCase):
    '''test lint_dnsname_underscore_in_sld.py'''
    def test_DNSNameUnderscoreInSLD(self):
        certPath ='..\\testCerts\\dnsNameUnderscoreInSLD.pem'
        lint_dnsname_underscore_in_sld.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_underscore_in_sld"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_DNSNameNoUnderscoreInSLD(self):
        certPath ='..\\testCerts\\dnsNameNoUnderscoreInSLD.pem'
        lint_dnsname_underscore_in_sld.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_underscore_in_sld"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
