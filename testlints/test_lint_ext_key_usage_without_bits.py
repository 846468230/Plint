import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_key_usage_without_bits
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertKeyUsageWithoutBits(unittest.TestCase):
    '''test lint_ext_key_usage_without_bits.py'''
    def test_SubCertKeyUsageWithoutBits(self):
        certPath ='..\\testCerts\\keyUsageNoBits.pem'
        lint_ext_key_usage_without_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_key_usage_without_bits"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_SubCertKeyUsageWithBits(self):
        certPath ='..\\testCerts\\caKeyUsageCrit.pem'
        lint_ext_key_usage_without_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_key_usage_without_bits"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubCertKeyUsageNotIncludedBits(self):
        certPath ='..\\testCerts\\caKeyUsageMissing.pem'
        lint_ext_key_usage_without_bits.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_key_usage_without_bits"].Execute(cert)
            self.assertEqual(base.LintStatus.NA,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
