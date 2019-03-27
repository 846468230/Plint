import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_san_not_critical_without_subject
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubjectEmptySANNotCrit(unittest.TestCase):
    '''test lint_ext_san_not_critical_without_subject.py'''
    def test_SubjectEmptySANNotCrit(self):
        certPath ='..\\testCerts\\SANSubjectEmptyNotCritical.pem'
        lint_ext_san_not_critical_without_subject.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_not_critical_without_subject"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SubjectEmptySANCrit(self):
        certPath ='..\\testCerts\\subCaEmptySubject.pem'
        lint_ext_san_not_critical_without_subject.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_not_critical_without_subject"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
    
    def test_SubjectNotEmptySANCrit(self):
        certPath ='..\\testCerts\\SANCriticalSubjectUncommonOnly.pem'
        lint_ext_san_not_critical_without_subject.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_not_critical_without_subject"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
