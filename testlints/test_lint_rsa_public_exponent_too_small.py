import sys
sys.path.append("..")
from lints import base
from lints import lint_rsa_public_exponent_too_small
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaExpTooSmall(unittest.TestCase):
    '''test lint_rsa_public_exponent_too_small.py'''
    def test_RsaExpTooSmall(self):
        certPath ='..\\testCerts\\badRsaExpLength.pem'
        lint_rsa_public_exponent_too_small.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_rsa_public_exponent_too_small"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_RsaExpNotTooSmall(self):
        certPath ='..\\testCerts\\goodRsaExpLength.pem'
        lint_rsa_public_exponent_too_small.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_rsa_public_exponent_too_small"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)