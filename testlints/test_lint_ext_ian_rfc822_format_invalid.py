import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_ian_rfc822_format_invalid
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANInvalidEmail(unittest.TestCase):
    '''test lint_ext_ian_rfc822_format_invalid.py'''
    def test_IANInvalidEmail(self):
        certPath ='..\\testCerts\\IANInvalidEmail.pem'
        lint_ext_ian_rfc822_format_invalid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_rfc822_format_invalid"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_IANValidEmail(self):
        certPath ='..\\testCerts\\IANValidEmail.pem'
        lint_ext_ian_rfc822_format_invalid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_rfc822_format_invalid"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
