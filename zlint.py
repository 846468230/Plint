from cryptography.x509 import Version
import lints.base as base
from lints.base import Lints
Version=Version.v3
import json
import datetime

class ResultSet:
    def __init__(self):
        self.Version=0
        self.Timestamp=0
        self.Results={}
        self.NoticesPresent=False
        self.WarningsPresent=False
        self.ErrorsPresent=False
        self.FatalsPresent=False
    
    def execute(self,cert):
        for name,l in base.Lints.items():
            res = l.Execute(cert)
            self.Results[name]=res
            self.updateErrorStatePresent(res)
    
    def updateErrorStatePresent(self,result):
        if  result.Status is base.LintStatus.Notice:
            self.NoticesPresent = True
        elif result.Status is base.LintStatus.Warn:
            self.WarningsPresent = True
        elif result.Status is base.LintStatus.Error:
            self.ErrorsPresent = True
        elif result.Status is base.LintStatus.Fatal:
            self.FatalsPresent = True

    def Tojson(result):
        dict={'version':'3','timestamp':result.Timestamp.strftime("%Y-%m-%d %H:%M:%S"),'notices_present':result.NoticesPresent,'warnings_present':result.WarningsPresent,'errors_present':result.ErrorsPresent,'fatals_present':result.FatalsPresent,'results':{}}
        for key,value in result.Results.items():
            dict['results'][key]=value.String()
        return dict

def EncodeLintDescriptionsToJSON():
    print(json.dumps(Lints,indent =4,separators=(',', ': '),ensure_ascii=True,default=base.Lint.Tojson))#sort_keys=True,


def LintCertificate(c):
    global Version
    res = ResultSet()
    res.execute(c)
    res.Version = Version
    res.Timestamp = datetime.datetime.now()
    return res
