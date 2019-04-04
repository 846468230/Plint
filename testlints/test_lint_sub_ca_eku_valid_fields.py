import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_ca_eku_valid_fields
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCAEKUValidFields(unittest.TestCase):
    '''test lint_sub_ca_eku_valid_fields.py'''
    def test_SubCAEKUValidFields(self):
        certPath ='..\\testCerts\\subCAEKUValidFields.pem'
        lint_sub_ca_eku_valid_fields.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_sub_ca_eku_not_technically_constrained"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubCAEKUNotValidFields(self):
        certPath ='..\\testCerts\\subCAEKUNotValidFields.pem'
        lint_sub_ca_eku_valid_fields.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_sub_ca_eku_not_technically_constrained"].Execute(cert)
            self.assertEqual(base.LintStatus.NA,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)