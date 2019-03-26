import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_key_usage_not_critical
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubCertKeyUsageNotCrit(unittest.TestCase):
    '''test lint_ext_key_usage_not_critical.py'''
    def test_SubCertKeyUsageNotCrit(self):
        certPath ='..\\testCerts\\keyUsageNotCriticalSubCert.pem'
        lint_ext_key_usage_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_key_usage_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
        
    def test_SubCaKeyUsageNotCrit(self):
        certPath ='..\\testCerts\\caKeyUsageNotCrit.pem'
        lint_ext_key_usage_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_key_usage_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Warn,out.Status)
    
    def test_SubCertKeyUsageCrit(self):
        certPath ='..\\testCerts\\domainValGoodSubject.pem'
        lint_ext_key_usage_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_key_usage_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
    
    def test_CaKeyUsageCrit(self):
        certPath ='..\\testCerts\\caKeyUsageCrit.pem'
        lint_ext_key_usage_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_key_usage_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubCertKeyUsageNotIncludedCrit(self):
        certPath ='..\\testCerts\\caKeyUsageMissing.pem'
        lint_ext_key_usage_not_critical.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["w_ext_key_usage_not_critical"].Execute(cert)
            self.assertEqual(base.LintStatus.NA,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
