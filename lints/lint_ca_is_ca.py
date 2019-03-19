#!/usr/bin/python
# -*- coding: UTF-8 -*-
from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca


class caIsCA(base.LintInterface):
    
    def Initialize(self):
        return 0

    def CheckApplies(self,c):
        try:
            return ca.IsExtInCert(c,ExtensionOID.KEY_USAGE) and c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature and ca.IsExtInCert(c,ExtensionOID.BASIC_CONSTRAINTS)
        except:
            return True

    def Execute(self,c):
        try:
            e = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if e.value.ca:
                return  base.LintResult(base.LintStatus.Pass)
            else:
                return  base.LintResult(base.LintStatus.Error)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.Error)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)

def init():
    base.RegisterLint(base.Lint("e_ca_is_ca","Root and Sub CA Certificate: The CA field MUST be set to true.","BRs: 7.1.2.1, BRs: 7.1.2.2",base.LintSource.CABFBaselineRequirements,Time.CABEffectiveDate,caIsCA()))