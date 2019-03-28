import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_subject_directory_attr_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSdaCrit(unittest.TestCase):
    '''test lint_ext_subject_directory_attr_critical.py'''
    def test_SdaCrit(self):
        certPath ='..\\testCerts\\subDirAttCritical.pem'
        lint_ext_subject_directory_attr_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_subject_directory_attr_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SdaNotCrit(self):
        certPath ='..\\testCerts\\RFC5280example2.pem'
        lint_ext_subject_directory_attr_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_subject_directory_attr_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
