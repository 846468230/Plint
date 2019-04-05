import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_certificate_policies_missing
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertPolicyMissing(unittest.TestCase):
    '''test lint_sub_cert_certificate_policies_missing.py'''
    def test_SubCertPolicyMissing(self):
        certPath ='..\\testCerts\\subCertPolicyMissing.pem'
        lint_sub_cert_certificate_policies_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_certificate_policies_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubCertPolicyPresent(self):
        certPath ='..\\testCerts\\subCertPolicyNoCrit.pem'
        lint_sub_cert_certificate_policies_missing.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_certificate_policies_missing"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)