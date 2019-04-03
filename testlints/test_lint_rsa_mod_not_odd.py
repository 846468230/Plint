import sys
sys.path.append("..")
from lints import base
from lints import lint_rsa_mod_not_odd
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaModEven(unittest.TestCase):
    '''test lint_rsa_mod_not_odd.py'''
    def test_RsaModEven(self):
        certPath ='..\\testCerts\\evenRsaMod.pem'
        lint_rsa_mod_not_odd.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_rsa_mod_not_odd"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_RsaModOdd(self):
        certPath ='..\\testCerts\\oddRsaMod.pem'
        lint_rsa_mod_not_odd.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_rsa_mod_not_odd"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)