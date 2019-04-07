import sys
sys.path.append("..")
from lints import base
from lints import lint_subject_dn_serial_number_max_length
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSubjectDNSerialNumberBelowMaximumLengthGood(unittest.TestCase):
    '''test lint_subject_dn_serial_number_max_length.py'''
    def test_SubjectDNSerialNumberBelowMaximumLengthGood(self):
        certPath ='..\\testCerts\\evAllGood.pem'
        lint_subject_dn_serial_number_max_length.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_dn_serial_number_max_length"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SubjectDNSerialNumberTooLongBad(self):
        certPath ='..\\testCerts\\SubjectDNSerialNumberTooLong.pem'
        lint_subject_dn_serial_number_max_length.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_subject_dn_serial_number_max_length"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)