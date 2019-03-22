import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_aia_marked_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestAiaCrit(unittest.TestCase):
    '''test lint_ext_aia_marked_critical.py'''
    def test_AiaCrit(self):
        certPath ='..\\testCerts\\caCommonNameMissing.pem'
        lint_ext_aia_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_aia_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_AiaNotCrit(self):
        certPath ='..\\testCerts\\subCAAIAValid.pem'
        lint_ext_aia_marked_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_aia_marked_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
