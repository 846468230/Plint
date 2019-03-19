import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_bad_character_in_label
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestBadCharacterInDNSLabel(unittest.TestCase):
    '''test lint_dnsname_bad_character_in_label.py'''
    def test_BadCharacterInDNSLabel(self):
        certPath ='..\\testCerts\\dnsNameBadCharacterInLabel.pem'
        lint_dnsname_bad_character_in_label.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_bad_character_in_label"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)
        
    def test_ClientDNSCertificate(self):
        certPath ='..\\testCerts\\dnsNameClientCert.pem'
        lint_dnsname_bad_character_in_label.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_bad_character_in_label"].Execute(cert)
            self.assertEqual(base.LintStatus.NA,out.Status)

    def test_ClientValidCertificate(self):
        certPath ='..\\testCerts\\validComodo.pem'
        lint_dnsname_bad_character_in_label.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_bad_character_in_label"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
