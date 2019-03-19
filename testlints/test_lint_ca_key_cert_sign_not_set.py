import sys
sys.path.append("..")
from lints import base
from lints import lint_ca_key_cert_sign_not_set
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCaKeyUsageNoCertSign(unittest.TestCase):
    '''test lint_ca_key_cert_sign_not_set.py'''
    def test_CaKeyUsageNoCertSign(self):
        certPath ='..\\testCerts\\caKeyUsageNoCertSign.pem'
        lint_ca_key_cert_sign_not_set.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_key_cert_sign_not_set"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_KeyUsageCertSign(self):
        certPath ='..\\testCerts\\caKeyUsageCrit.pem'
        lint_ca_key_cert_sign_not_set.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ca_key_cert_sign_not_set"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)