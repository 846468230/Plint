import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_duplicate_extension
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDuplicateExtension(unittest.TestCase):
    '''test lint_ext_duplicate_extension.py'''
    def test_DuplicateExtension(self):
        certPath ='..\\testCerts\\extSANDuplicated.pem'
        lint_ext_duplicate_extension.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_duplicate_extension"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_NoDuplicateExtension(self):
        certPath ='..\\testCerts\\caBasicConstCrit.pem'
        lint_ext_duplicate_extension.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_duplicate_extension"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
