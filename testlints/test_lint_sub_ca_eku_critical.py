import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_ca_eku_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCaEkuCrit(unittest.TestCase):
    '''test lint_sub_ca_eku_critical.py'''
    def test_SubCaCrlMissing(self):
        certPath ='..\\testCerts\\subCAWEkuCrit.pem'
        lint_sub_ca_eku_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_ca_eku_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_SubCaEkuNotCrit(self):
        certPath ='..\\testCerts\\subCAWEkuNoCrit.pem'
        lint_sub_ca_eku_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_ca_eku_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)