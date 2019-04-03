import sys
sys.path.append("..")
from lints import base
from lints import lint_san_bare_wildcard
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestBrSANBareWildcard(unittest.TestCase):
    '''test lint_san_bare_wildcard.py'''
    def test_RsaExpTooSmall(self):
        certPath ='..\\testCerts\\SANBareWildcard.pem'
        lint_san_bare_wildcard.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_bare_wildcard"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_BrSANNotBareWildcard(self):
        certPath ='..\\testCerts\\SANURIValid.pem'
        lint_san_bare_wildcard.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_bare_wildcard"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)