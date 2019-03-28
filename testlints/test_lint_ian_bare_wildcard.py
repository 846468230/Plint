import sys
sys.path.append("..")
from lints import base
from lints import lint_ian_bare_wildcard
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestBrIANBareWildcard(unittest.TestCase):
    '''test lint_ian_bare_wildcard.py'''
    def test_BrIANBareWildcard(self):
        certPath ='..\\testCerts\\IANBareWildcard.pem'
        lint_ian_bare_wildcard.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ian_bare_wildcard"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_BrIANNotBareWildcard(self):
        certPath ='..\\testCerts\\IANCritical.pem'
        lint_ian_bare_wildcard.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ian_bare_wildcard"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
