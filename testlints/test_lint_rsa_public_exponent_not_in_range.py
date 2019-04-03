import sys
sys.path.append("..")
from lints import base
from lints import lint_rsa_public_exponent_not_in_range
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaExpNotInRange(unittest.TestCase):
    '''test lint_rsa_public_exponent_not_in_range.py'''
    def test_RsaExpNotInRange(self):
        certPath ='..\\testCerts\\badRsaExp.pem'
        lint_rsa_public_exponent_not_in_range.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_rsa_public_exponent_not_in_range"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_RsaExpInRange(self):
        certPath ='..\\testCerts\\validRsaExpRange.pem'
        lint_rsa_public_exponent_not_in_range.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_rsa_public_exponent_not_in_range"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)