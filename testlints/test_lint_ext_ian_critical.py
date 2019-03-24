import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_ian_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANCrit(unittest.TestCase):
    '''test lint_ext_ian_critical.py'''
    def test_IANCrit(self):
        certPath ='..\\testCerts\\IANCritical.pem'
        lint_ext_ian_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_ian_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
        
    def test_IANNotCrit(self):
        certPath ='..\\testCerts\\IANNotCritical.pem'
        lint_ext_ian_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_ian_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
