import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_ian_no_entries
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANNoEntry(unittest.TestCase):
    '''test lint_ext_ian_no_entries.py'''
    def test_IANNoEntry(self):
        certPath ='..\\testCerts\\IANEmpty.pem'
        lint_ext_ian_no_entries.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_no_entries"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_IANHasEntry(self):
        certPath ='..\\testCerts\\IANDNSIA5String.pem'
        lint_ext_ian_no_entries.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_ian_no_entries"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
