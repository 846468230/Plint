import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_san_space_dns_name
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSANGood(unittest.TestCase):
    '''test lint_ext_san_space_dns_name.py'''
    def test_SANNoEntry(self):
        certPath ='..\\testCerts\\orgValGoodAllFields.pem'
        lint_ext_san_space_dns_name.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_space_dns_name"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SANSpace(self):
        certPath ='..\\testCerts\\SANWithSpaceDNS.pem'
        lint_ext_san_space_dns_name.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_space_dns_name"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
