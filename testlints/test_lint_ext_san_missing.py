import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_san_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestNoSAN(unittest.TestCase):
    '''test lint_ext_san_missing.py'''
    def test_NoSAN(self):
        certPath ='..\\testCerts\\subjectEmptyNoSAN.pem'
        lint_ext_san_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_HasSAN(self):
        certPath ='..\\testCerts\\orgValGoodAllFields.pem'
        lint_ext_san_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
