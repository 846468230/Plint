import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_key_usage_cert_sign_bit_set
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertSignBitSet(unittest.TestCase):
    '''test lint_sub_cert_key_usage_cert_sign_bit_set.py'''
    def test_CertSignBitSet(self):
        certPath ='..\\testCerts\\subKeyUsageInvalid.pem'
        lint_sub_cert_key_usage_cert_sign_bit_set.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_key_usage_cert_sign_bit_set"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CertSignBitNotSet(self):
        certPath ='..\\testCerts\\subKeyUsageValid.pem'
        lint_sub_cert_key_usage_cert_sign_bit_set.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_key_usage_cert_sign_bit_set"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)