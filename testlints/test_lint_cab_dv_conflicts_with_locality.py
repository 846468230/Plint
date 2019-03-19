import sys
sys.path.append("..")
from lints import base
from lints import lint_cab_dv_conflicts_with_locality
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCertPolicyNotConflictWithLocal(unittest.TestCase):
    '''test lint_cab_dv_conflicts_with_locality.py'''
    def test_CertPolicyNotConflictWithLocal(self):
        certPath ='..\\testCerts\\domainValGoodSubject.pem'
        lint_cab_dv_conflicts_with_locality.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cab_dv_conflicts_with_locality"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_CertPolicyConflictsWithLocal(self):
        certPath ='..\\testCerts\\domainValWithLocal.pem'
        lint_cab_dv_conflicts_with_locality.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_cab_dv_conflicts_with_locality"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)