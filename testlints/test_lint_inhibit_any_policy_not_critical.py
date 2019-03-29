import sys
sys.path.append("..")
from lints import base
from lints import lint_inhibit_any_policy_not_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestInhibitAnyPolicyNotCrit(unittest.TestCase):
    '''test lint_inhibit_any_policy_not_critical.py'''
    def test_InhibitAnyPolicyNotCrit(self):
        certPath ='..\\testCerts\\utf8NoControl.pem'
        lint_inhibit_any_policy_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_inhibit_any_policy_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_InhibitAnyPolicyCrit(self):
        certPath ='..\\testCerts\\inhibitAnyCrit.pem'
        lint_inhibit_any_policy_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_inhibit_any_policy_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
