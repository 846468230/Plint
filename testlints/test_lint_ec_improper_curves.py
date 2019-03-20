import sys
sys.path.append("..")
from lints import base
from lints import lint_ec_improper_curves
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestECP224(unittest.TestCase):
    '''test lint_ec_improper_curves.py'''
    def test_ECP224(self):
        certPath ='..\\testCerts\\ecdsaP224.pem'
        lint_ec_improper_curves.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ec_improper_curves"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_ECP256(self):
        certPath ='..\\testCerts\\ecdsaP384.pem'
        lint_ec_improper_curves.init()
        
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ec_improper_curves"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
    
    def test_ECP384(self):
        certPath ='..\\testCerts\\ecdsaP521.pem'
        lint_ec_improper_curves.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ec_improper_curves"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_ECP521(self):
        certPath ='..\\testCerts\\ecdsaP256.pem'
        lint_ec_improper_curves.init()
        
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ec_improper_curves"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
