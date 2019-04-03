import sys
sys.path.append("..")
from lints import base
from lints import lint_rsa_mod_less_than_2048_bits
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaModSizeSmall(unittest.TestCase):
    '''test lint_rsa_mod_less_than_2048_bits.py'''
    def test_RsaModSizeSmall(self):
        certPath ='..\\testCerts\\noRsaLength.pem'
        lint_rsa_mod_less_than_2048_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_rsa_mod_less_than_2048_bits"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_RsaModSizeNotSmall(self):
        certPath ='..\\testCerts\\yesRsaLength.pem'
        lint_rsa_mod_less_than_2048_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_rsa_mod_less_than_2048_bits"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)