import sys
sys.path.append("..")
from lints import base
from lints import lint_rsa_public_exponent_not_odd
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaExpEven(unittest.TestCase):
    '''test lint_rsa_public_exponent_not_odd.py'''
    def test_RsaExpNotInRange(self):
        certPath ='..\\testCerts\\badRsaExp.pem'
        lint_rsa_public_exponent_not_odd.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_rsa_public_exponent_not_odd"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_RsaExpOdd(self):
        certPath ='..\\testCerts\\goodRsaExp.pem'
        lint_rsa_public_exponent_not_odd.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_rsa_public_exponent_not_odd"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)