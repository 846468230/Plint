import sys
sys.path.append("..")
from lints import base
from lints import lint_cab_ov_requires_org
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertPolicyOvHasOrg(unittest.TestCase):
    '''test lint_cab_iv_requires_personal_name.py'''
    def test_CertPolicyOvHasOrg(self):
        certPath ='..\\testCerts\\orgValGoodAllFields.pem'
        lint_cab_ov_requires_org.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cab_ov_requires_org"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_CertPolicyOvNoOrg(self):
        certPath ='..\\testCerts\\orgValNoOrg.pem'
        lint_cab_ov_requires_org.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cab_ov_requires_org"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)