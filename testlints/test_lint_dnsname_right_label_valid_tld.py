import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_right_label_valid_tld
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameValidTLD(unittest.TestCase):
    '''test lint_dnsname_right_label_valid_tld.py'''
    def test_DNSNameHyphenBeginningSLD(self):
        certPath ='..\\testCerts\\dnsNameValidTLD.pem'
        lint_dnsname_right_label_valid_tld.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_not_valid_tld"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_DNSNameNotValidTLD(self):
        certPath ='..\\testCerts\\dnsNameNotValidTLD.pem'
        lint_dnsname_right_label_valid_tld.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_not_valid_tld"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_DNSNameNotYetValidTLD(self):
        certPath ='..\\testCerts\\dnsNameNotYetValidTLD.pem'
        lint_dnsname_right_label_valid_tld.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_not_valid_tld"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_DNSNameNoLongerValidTLD(self):
        certPath ='..\\testCerts\\dnsNameNoLongerValidTLD.pem'
        lint_dnsname_right_label_valid_tld.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_not_valid_tld"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_DNSNameWasValidTLD(self):
        certPath ='..\\testCerts\\dnsNameWasValidTLD.pem'
        lint_dnsname_right_label_valid_tld.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_not_valid_tld"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_DNSNameOnionTLD(self):
        certPath ='..\\testCerts\\dnsNameOnionTLD.pem'
        lint_dnsname_right_label_valid_tld.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_not_valid_tld"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_DNSNameWithIPInCommonName(self):
        certPath ='..\\testCerts\\dnsNameWithIPInCN.pem'
        lint_dnsname_right_label_valid_tld.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_not_valid_tld"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
