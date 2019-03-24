import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_cert_policy_error
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertPolicyError(unittest.TestCase):
    '''test lint_ext_cert_policy_error.py'''
    def test_CertPolicyError(self):
        certPath ='..\\testCerts\\utf8NoControl.pem'
        lint_ext_cert_policy_error.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_error"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_CertPolicyParsed(self):
        certPath ='..\\testCerts\\subjectLocalityNameLengthGood.pem'
        lint_ext_cert_policy_error.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_error"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
