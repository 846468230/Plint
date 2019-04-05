import sys
sys.path.append("..")
from lints import base
from lints import lint_sub_ca_name_constraints_not_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCaNcNotCrit(unittest.TestCase):
    '''test lint_sub_ca_name_constraints_not_critical.py'''
    def test_SubCaNcNotCrit(self):
        certPath ='..\\testCerts\\subCAWNameConstNoCrit.pem'
        lint_sub_ca_name_constraints_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_ca_name_constraints_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)

    def test_SubCaNcCrit(self):
        certPath ='..\\testCerts\\subCAWNameConstCrit.pem'
        lint_sub_ca_name_constraints_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_sub_ca_name_constraints_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)