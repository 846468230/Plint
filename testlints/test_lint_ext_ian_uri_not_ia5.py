import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_ian_uri_not_ia5
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANURIIA5(unittest.TestCase):
    '''test lint_ext_ian_uri_not_ia5.py'''
    def test_IANURIIA5(self):
        certPath ='..\\testCerts\\IANURIIA5String.pem'
        lint_ext_ian_uri_not_ia5.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_uri_not_ia5"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_IANURINotIA5(self):
        certPath ='..\\testCerts\\IANURINotIA5String.pem'
        lint_ext_ian_uri_not_ia5.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_uri_not_ia5"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
