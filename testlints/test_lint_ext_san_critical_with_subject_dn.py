import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_san_critical_with_subject_dn
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSANCritWithSubjectDn(unittest.TestCase):
    '''test lint_ext_san_critical_with_subject_dn.py'''
    def test_SANCritWithSubjectDn(self):
        certPath ='..\\testCerts\\SANCriticalSubjectUncommonOnly.pem'
        lint_ext_san_critical_with_subject_dn.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_san_critical_with_subject_dn"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
        
    def test_SANNotCritWithSubjectDn(self):
        certPath ='..\\testCerts\\indivValGoodAllFields.pem'
        lint_ext_san_critical_with_subject_dn.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_san_critical_with_subject_dn"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
