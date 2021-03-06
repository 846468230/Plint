import sys
sys.path.append("..")
from lints import base
from lints import lint_ca_digital_signature_not_set
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCaKeyUsageNoDigSign(unittest.TestCase):
    '''test lint_ca_digital_signature_not_set.py'''
    def test_CaKeyUsageNoDigSign(self):
        certPath ='..\\testCerts\\caKeyUsageNoCertSign.pem'
        lint_ca_digital_signature_not_set.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_ca_digital_signature_not_set"].Execute(cert)
            self.assertEqual(base.LintStatus.Notice,out.Status)
        
    def test_KeyUsageDigSign(self):
        certPath ='..\\testCerts\\caKeyUsageWDigSign.pem'
        lint_ca_digital_signature_not_set.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["n_ca_digital_signature_not_set"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)