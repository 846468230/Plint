import sys
sys.path.append("..")
from lints import base
from lints import lint_rsa_exp_negative
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestRsaExpPositive(unittest.TestCase):
    '''test lint_rsa_exp_negative.py'''
    def test_RootCAKeyUsageMissing(self):
        certPath ='..\\testCerts\\IANURIValid.pem'
        lint_rsa_exp_negative.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_rsa_exp_negative"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)