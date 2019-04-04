import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_ca_eku_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCaEkuMissing(unittest.TestCase):
    '''test lint_sub_ca_eku_missing.py'''
    def test_SubCaEkuMissing(self):
        certPath ='..\\testCerts\\subCAEKUMissing.pem'
        lint_sub_ca_eku_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_sub_ca_eku_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Notice,out.Status)

    def test_SubCaEkuNotMissing(self):
        certPath ='..\\testCerts\\subCAWEkuCrit.pem'
        lint_sub_ca_eku_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_sub_ca_eku_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)