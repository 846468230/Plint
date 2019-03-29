import sys
sys.path.append("..")
from lints import base
from lints import lint_idn_dnsname_must_be_nfc
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIDNDnsNameNotNFC(unittest.TestCase):
    '''test lint_idn_dnsname_must_be_nfc.py'''
    def test_IDNDnsNameNotNFC(self):
        certPath ='..\\testCerts\\dnsNamesNotNFC.pem'
        lint_idn_dnsname_must_be_nfc.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_international_dns_name_not_nfc"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_IDNDnsNameIsNFC(self):
        certPath ='..\\testCerts\\dnsNamesNFC.pem'
        lint_idn_dnsname_must_be_nfc.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_international_dns_name_not_nfc"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
