import sys
sys.path.append("..")
from lints import base
from lints import lint_cab_dv_conflicts_with_org
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertPolicyNotConflictWithOrg(unittest.TestCase):
    '''test lint_cab_dv_conflicts_with_org.py'''
    def test_CertPolicyNotConflictWithOrg(self):
        certPath ='..\\testCerts\\domainValGoodSubject.pem'
        lint_cab_dv_conflicts_with_org.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cab_dv_conflicts_with_org"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_CertPolicyConflictsWithOrg(self):
        certPath ='..\\testCerts\\domainValWithOrg.pem'
        lint_cab_dv_conflicts_with_org.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cab_dv_conflicts_with_org"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)