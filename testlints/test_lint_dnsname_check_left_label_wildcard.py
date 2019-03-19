import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_check_left_label_wildcard
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestLeftLabelWildcardCorrect(unittest.TestCase):
    '''test lint_dnsname_check_left_label_wildcard.py'''
    def test_LeftLabelWildcardCorrect(self):
        certPath ='..\\testCerts\\dnsNameWildcardCorrect.pem'
        lint_dnsname_check_left_label_wildcard.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_left_label_wildcard_correct"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_LeftLabelWildcardIncorrect(self):
        certPath ='..\\testCerts\\dnsNameWildcardIncorrect.pem'
        lint_dnsname_check_left_label_wildcard.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_left_label_wildcard_correct"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
