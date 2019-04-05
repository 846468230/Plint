import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_eku_extra_values
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestEkuExtra(unittest.TestCase):
    '''test lint_sub_cert_eku_extra_values.py'''
    def test_CrlCrit(self):
        certPath ='..\\testCerts\\subExtKeyUsageServClientEmailCodeSign.pem'
        lint_sub_cert_eku_extra_values.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_cert_eku_extra_values"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_EkuNoExtra(self):
        certPath ='..\\testCerts\\subExtKeyUsageServClientEmail.pem'
        lint_sub_cert_eku_extra_values.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_cert_eku_extra_values"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)