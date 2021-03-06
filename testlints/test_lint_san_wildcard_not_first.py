import sys
sys.path.append("..")
from lints import base
from lints import lint_san_wildcard_not_first
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestBrSANWildcardFirst(unittest.TestCase):
    '''test lint_san_wildcard_not_first.py'''
    def test_BrSANWildcardFirst(self):
        certPath ='..\\testCerts\\SANWildcardFirst.pem'
        lint_san_wildcard_not_first.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_wildcard_not_first"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_BrSANWildcardNotFirst(self):
        certPath ='..\\testCerts\\SANURIValid.pem'
        lint_san_wildcard_not_first.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_wildcard_not_first"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)