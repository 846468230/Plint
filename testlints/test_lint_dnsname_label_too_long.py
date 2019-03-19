import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_label_too_long
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestDNSNameLabelTooLong(unittest.TestCase):
    '''test lint_dnsname_label_too_long.py'''        
    def test_DNSNameLabelTooLong(self):
        certPath ='..\\testCerts\\dnsNameLabelTooLong.pem'
        lint_dnsname_label_too_long.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_label_too_long"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
