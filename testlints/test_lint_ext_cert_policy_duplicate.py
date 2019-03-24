import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_cert_policy_duplicate
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertPolicyDuplicated(unittest.TestCase):
    '''test lint_ext_cert_policy_duplicate.py'''
    def test_CertPolicyDuplicated(self):
        certPath ='..\\testCerts\\certPolicyDuplicateShort.pem'
        lint_ext_cert_policy_duplicate.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_duplicate"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_CertPolicyDuplicatedAssertion(self):
        certPath ='..\\testCerts\\certPolicyAssertionDuplicated.pem'
        lint_ext_cert_policy_duplicate.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_duplicate"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
    
    def testCertPolicyNotDuplicated(self):
        certPath ='..\\testCerts\\certPolicyNoDuplicate.pem'
        lint_ext_cert_policy_duplicate.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_duplicate"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
