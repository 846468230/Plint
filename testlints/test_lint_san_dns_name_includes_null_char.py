import sys
sys.path.append("..")
from lints import base
from lints import lint_san_dns_name_includes_null_char
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestBrSANDNSNull(unittest.TestCase):
    '''test lint_san_dns_name_includes_null_char.py'''
    def test_BrSANDNSNull(self):
        certPath ='..\\testCerts\\SANDNSNull.pem'
        lint_san_dns_name_includes_null_char.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_dns_name_includes_null_char"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SANDNSNotNull(self):
        certPath ='..\\testCerts\\SANURIValid.pem'
        lint_san_dns_name_includes_null_char.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_san_dns_name_includes_null_char"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)