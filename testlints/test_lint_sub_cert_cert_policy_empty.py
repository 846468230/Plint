import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_cert_policy_empty
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertPolicyMissing(unittest.TestCase):
    '''test lint_sub_cert_cert_policy_empty.py'''
    def test_CertPolicyMissing(self):
        certPath ='..\\testCerts\\subCertPolicyMissing.pem'
        lint_sub_cert_cert_policy_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_cert_policy_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CertPolicyPresent(self):
        certPath ='..\\testCerts\\subCertPolicyNoCrit.pem'
        lint_sub_cert_cert_policy_empty.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_cert_policy_empty"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)