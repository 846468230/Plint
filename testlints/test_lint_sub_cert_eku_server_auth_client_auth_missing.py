import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_eku_server_auth_client_auth_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestEkuBothPres(unittest.TestCase):
    '''test lint_sub_cert_eku_server_auth_client_auth_missing.py'''
    def test_EkuBothPres(self):
        certPath ='..\\testCerts\\subExtKeyUsageCodeSign.pem'
        lint_sub_cert_eku_server_auth_client_auth_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_eku_server_auth_client_auth_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.NA,out.Status)

    def test_EkuNeitherPres(self):
        certPath ='..\\testCerts\\subExtKeyUsageServClient.pem'
        lint_sub_cert_eku_server_auth_client_auth_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_eku_server_auth_client_auth_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)