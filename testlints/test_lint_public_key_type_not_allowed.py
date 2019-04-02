import sys
sys.path.append("..")
from lints import base
from lints import lint_public_key_type_not_allowed
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestPKTypeUnknown(unittest.TestCase):
    '''test lint_public_key_type_not_allowed.py'''
    def test_PKTypeUnknown(self):
        certPath ='..\\testCerts\\unknownpublickey.pem'
        lint_public_key_type_not_allowed.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_public_key_type_not_allowed"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_PKTypeRSA(self):
        certPath ='..\\testCerts\\rsawithsha1before2016.pem'
        lint_public_key_type_not_allowed.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_public_key_type_not_allowed"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def testPKTypeECDSA(self):
        certPath ='..\\testCerts\\ecdsaP256.pem'
        lint_public_key_type_not_allowed.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_public_key_type_not_allowed"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
