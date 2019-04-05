import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_certificate_policies_marked_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertPolicyCrit(unittest.TestCase):
    '''test lint_sub_cert_certificate_policies_marked_critical.py'''
    def test_SubCertPolicyCrit(self):
        certPath ='..\\testCerts\\subCertPolicyCrit.pem'
        lint_sub_cert_certificate_policies_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_cert_certificate_policies_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_SubCertPolicyNotCrit(self):
        certPath ='..\\testCerts\\subCertPolicyNoCrit.pem'
        lint_sub_cert_certificate_policies_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_cert_certificate_policies_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)