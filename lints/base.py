import datetime
from abc import ABCMeta, abstractmethod
import util
Lints={}
SourceName=["UnknownLintSource","CABFBaselineRequirements","RFC5280","RFC5891","ZLint","AWSLabs"]
class LintInterface(metaclass=ABCMeta):

    @abstractmethod
    def Initialize():
        pass

    @abstractmethod
    def CheckApplies(c):
        pass

    @abstractmethod
    def Execute(c):
        pass

class LintSource:
    UnknownLintSource=0
    CABFBaselineRequirements=1
    RFC5280=2
    RFC5891=3
    ZLint=4
    AWSLabs=5

    def sourcename(source):
        return SourceName[source]

class Lint:

    def __init__(self,Name,Description,Citation,Source,EffectiveDate,Lint):
        self.Name=Name
        self.Description=Description
        self.Citation=Citation
        self.Source=Source
        self.EffectiveDate=EffectiveDate
        self.Lint=Lint
    
    def CheckEffective(self,c):
        if self.EffectiveDate==datetime.datetime(1,1,1,0,0,0,0) or  not self.EffectiveDate > c.not_valid_before:
            return True
        return False
    
    def Execute(self,cert):
        if self.Source==LintSource.CABFBaselineRequirements and not util.ca.IsServerAuthCert(cert) :
            return LintResult(LintStatus.NA)
        if not self.Lint.CheckApplies(cert):
            return LintResult(LintStatus.NA)
        elif not self.CheckEffective(cert):
            return LintResult(LintStatus.NE)
        res=self.Lint.Execute(cert)
        return res

    def Tojson(cls):
        dict={'name':cls.Name,'description':cls.Description,'citation':cls.Citation,'source':LintSource.sourcename(cls.Source),'effectiveDate':cls.EffectiveDate.strftime("%Y-%m-%d %H:%M:%S")}
        return dict


def RegisterLint(l):
    global Lints
    try:
        l.Lint.Initialize()
    except:
        print("could not initialize lint:"+l.Name)
    Lints[l.Name] = l


class LintStatus:
    Reserved=0
    NA=1
    NE=2
    Pass=3
    Notice=4
    Warn=5
    Error=6
    Fatal=7

    def __init__(self,e):
        self.e=e

    def MarshalJSON():
        pass

    
class LintResult:

    def __init__(self,Status,Details=''):
        self.Status=Status
        self.Details=Details

    def String(self):
        if self.Status is LintStatus.NA:
            return "NA"
        elif self.Status is LintStatus.NE:
            return "NE"
        elif self.Status is LintStatus.Pass:
            return "pass"
        elif self.Status is LintStatus.Notice:
            return "info"
        elif self.Status is LintStatus.Warn:
            return "warn"
        elif self.Status is LintStatus.Error:
            return "error"
        elif self.Status is LintStatus.Fatal:
            return "fatal"
        else:
            return ""