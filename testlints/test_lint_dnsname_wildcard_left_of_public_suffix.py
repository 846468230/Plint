import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_wildcard_left_of_public_suffix
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestWildcardLeftOfPublicSuffix(unittest.TestCase):
    '''test lint_dnsname_wildcard_left_of_public_suffix.py'''
    def test_WildcardLeftOfPublicSuffix(self):
        certPath ='..\\testCerts\\dnsNameWildcardLeftOfPublicSuffix.pem'
        lint_dnsname_wildcard_left_of_public_suffix.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_dnsname_wildcard_left_of_public_suffix"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
        
    def test_WildcardNotLeftOfPublicSuffix(self):
        certPath ='..\\testCerts\\dnsNameWildcardNotLeftOfPublicSuffix.pem'
        lint_dnsname_wildcard_left_of_public_suffix.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_dnsname_wildcard_left_of_public_suffix"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
