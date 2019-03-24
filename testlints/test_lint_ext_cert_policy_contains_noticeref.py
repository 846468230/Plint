import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_cert_policy_contains_noticeref
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestNoticeRefUsed(unittest.TestCase):
    '''test lint_ext_cert_policy_contains_noticeref.py'''
    def test_NoticeRefUsed(self):
        certPath ='..\\testCerts\\utf8NoControl.pem'
        lint_ext_cert_policy_contains_noticeref.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_cert_policy_contains_noticeref"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
        
    def test_NoticeRefNotUsed(self):
        certPath ='..\\testCerts\\userNoticeUnrecommended.pem'
        lint_ext_cert_policy_contains_noticeref.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_cert_policy_contains_noticeref"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
