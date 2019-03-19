import sys
sys.path.append("..")
from lints import base
from lints import lint_cert_policy_iv_requires_country
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertPolicyIvCountry(unittest.TestCase):
    '''test lint_cab_iv_requires_personal_name.py'''
    def test_CertPolicyIvHasPerson(self):
        certPath ='..\\testCerts\\indivValGoodAllFields.pem'
        lint_cert_policy_iv_requires_country.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cert_policy_iv_requires_country"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_CertPolicyIvNoCountry(self):
        certPath ='..\\testCerts\\indivValNoCountry.pem'
        lint_cert_policy_iv_requires_country.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cert_policy_iv_requires_country"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)