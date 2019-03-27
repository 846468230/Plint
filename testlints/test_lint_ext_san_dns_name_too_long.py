import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_san_dns_name_too_long
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSANDNSShort(unittest.TestCase):
    '''test lint_ext_san_dns_name_too_long.py'''
    def test_SANDNSShort(self):
        certPath ='..\\testCerts\\orgValGoodAllFields.pem'
        lint_ext_san_dns_name_too_long.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_dns_name_too_long"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SANDNSTooLong(self):
        certPath ='..\\testCerts\\SANDNSTooLong.pem'
        lint_ext_san_dns_name_too_long.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_dns_name_too_long"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
