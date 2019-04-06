import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_common_name_not_from_san
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestCnNotFromSAN(unittest.TestCase):
    '''test lint_subject_common_name_not_from_san.py'''
    def test_CnNotFromSAN(self):
        certPath ='..\\testCerts\\SANWithMissingCN.pem'
        lint_subject_common_name_not_from_san.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_common_name_not_from_san"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_CnFromSAN(self):
        certPath ='..\\testCerts\\SANRegisteredIdBeginning.pem'
        lint_subject_common_name_not_from_san.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_common_name_not_from_san"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
    
    def test_SANCaseNotMatchingCN(self):
        certPath ='..\\testCerts\\SANCaseNotMatchingCN.pem'
        lint_subject_common_name_not_from_san.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_common_name_not_from_san"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)