import sys
sys.path.append("..")
from lints import base
from lints import lint_ev_valid_time_too_long
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestEvValidTooLong(unittest.TestCase):
    '''test lint_ev_valid_time_too_long.py'''
    def test_EvValidTooLong(self):
        certPath ='..\\testCerts\\evValidTooLong.pem'
        lint_ev_valid_time_too_long.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ev_valid_time_too_long"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_EvValidNotTooLong(self):
        certPath ='..\\testCerts\\evValidNotTooLong.pem'
        lint_ev_valid_time_too_long.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ev_valid_time_too_long"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
