import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_hyphen_in_sld
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameHyphenBeginningSLD(unittest.TestCase):
    '''test lint_dnsname_hyphen_in_sld.py'''
    def test_DNSNameHyphenBeginningSLD(self):
        certPath ='..\\testCerts\\dnsNameHyphenBeginningSLD.pem'
        lint_dnsname_hyphen_in_sld.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_hyphen_in_sld"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_DNSNameHyphenEndingSLD(self):
        certPath ='..\\testCerts\\dnsNameHyphenBeginningSLD.pem'
        lint_dnsname_hyphen_in_sld.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_hyphen_in_sld"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_DNSNameNoHyphenInSLD(self):
        certPath ='..\\testCerts\\dnsNameWildcardCorrect.pem'
        lint_dnsname_hyphen_in_sld.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_hyphen_in_sld"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)
        
    def test_DNSNamePrivatePublicSuffixNoHyphenInSLD(self):
        certPath ='..\\testCerts\\dnsNamePrivatePublicSuffix.pem'
        lint_dnsname_hyphen_in_sld.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_hyphen_in_sld"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
