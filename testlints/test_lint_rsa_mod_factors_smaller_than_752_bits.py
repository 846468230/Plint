import sys
sys.path.append("..")
from lints import base
from lints import lint_rsa_mod_factors_smaller_than_752_bits
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaModFactorTooSmall(unittest.TestCase):
    '''test lint_rsa_mod_factors_smaller_than_752_bits.py'''
    def test_RsaModFactorTooSmall(self):
        certPath ='..\\testCerts\\evenRsaMod.pem'
        lint_rsa_mod_factors_smaller_than_752_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_rsa_mod_factors_smaller_than_752"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_RsaModFactorNotTooSmall(self):
        certPath ='..\\testCerts\\goodRsaExp.pem'
        lint_rsa_mod_factors_smaller_than_752_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_rsa_mod_factors_smaller_than_752"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)