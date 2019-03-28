import sys
sys.path.append("..")
from lints import base
from lints import lint_generalized_time_not_valid
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestGenralizedNotValid(unittest.TestCase):
    '''test lint_generalized_time_not_valid.py'''
    def test_GenralizedValid(self):
        certPath ='..\\testCerts\\generalizedHasSeconds.pem'
        lint_generalized_time_not_valid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_generalized_time_not_valid"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_GenralizedHasFriction(self):
        certPath ='..\\testCerts\\generalizedNoFraction.pem'
        lint_generalized_time_not_valid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_generalized_time_not_valid"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
    
    def test_GenralizedNotZulu(self):
        certPath ='..\\testCerts\\generalizedNotZulu.pem'
        lint_generalized_time_not_valid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_generalized_time_not_valid"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status) 

    def test_GenralizedNoSeconds(self):
        certPath ='..\\testCerts\\generalizedNoSeconds.pem'
        lint_generalized_time_not_valid.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_generalized_time_not_valid"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
