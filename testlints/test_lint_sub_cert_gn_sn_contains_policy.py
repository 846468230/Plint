import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_cert_gn_sn_contains_policy
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestGivenNameCorrectPolicy(unittest.TestCase):
    '''test lint_sub_cert_gn_sn_contains_policy.py'''
    def test_GivenNameCorrectPolicy(self):
        certPath ='..\\testCerts\\givenNameCorrectPolicy.pem'
        lint_sub_cert_gn_sn_contains_policy.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_given_name_surname_contains_correct_policy"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SurnameCorrectPolicy(self):
        certPath ='..\\testCerts\\surnameCorrectPolicy.pem'
        lint_sub_cert_gn_sn_contains_policy.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_given_name_surname_contains_correct_policy"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
    
    def test_GivenNameIncorrectPolicy(self):
        certPath ='..\\testCerts\\givenNameIncorrectPolicy.pem'
        lint_sub_cert_gn_sn_contains_policy.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_given_name_surname_contains_correct_policy"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SurnameIncorrectPolicy(self):
        certPath ='..\\testCerts\\surnameIncorrectPolicy.pem'
        lint_sub_cert_gn_sn_contains_policy.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_sub_cert_given_name_surname_contains_correct_policy"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)