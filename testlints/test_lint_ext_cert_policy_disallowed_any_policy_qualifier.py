import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_cert_policy_disallowed_any_policy_qualifier
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestNoticeRef(unittest.TestCase):
    '''test lint_ext_cert_policy_disallowed_any_policy_qualifier.py'''
    def test_NoticeRef(self):
        certPath ='..\\testCerts\\userNoticePres.pem'
        lint_ext_cert_policy_disallowed_any_policy_qualifier.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_disallowed_any_policy_qualifier"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_Cps(self):
        certPath ='..\\testCerts\\userNoticeMissing.pem'
        lint_ext_cert_policy_disallowed_any_policy_qualifier.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_disallowed_any_policy_qualifier"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
    
    def testNoticeRefUnknown(self):
        certPath ='..\\testCerts\\userNoticeUnrecommended.pem'
        lint_ext_cert_policy_disallowed_any_policy_qualifier.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_cert_policy_disallowed_any_policy_qualifier"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
