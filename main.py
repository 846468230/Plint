#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
dir = os.path.dirname(os.path.realpath(__file__))
import sys
sys.path.append(dir)
import pkgutil
from importlib import import_module
import getopt

from lints import base
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json
from util import crl,zlint

listLintsJSON = False
listLintsSchema = False
prettyprint = False
formatprint =""


def Usage():
    print(
        "[Usage]:The option -j is listing the lints into JSON format.\n[Usage]:The option -s is listing Lints schema.\n[Usage]:The -p is listing Lints pretty.\n[Usage]:The -f is one of {pem,der}.\n[Usage]:Please use -h or -? for help.\n")


def handleOption(argv):
    global listLintsJSON
    global listLintsSchema
    global prettyprint
    global formatprint
    try:
        opts, args = getopt.getopt(argv, "jsp:f:h?", ["path=","format="])
    except getopt.GetoptError:
        print("please input the right args，or input -h for help，and when inputting -f or --format the you must give one argv of{der,pem }")
        sys.exit(0)
    for opt, arg in opts:
        if opt == '-h' or opt == '?':
            Usage()
            sys.exit(0)
        elif opt == '-j':
            listLintsJSON = True
        elif opt == '-s':
            listLintsSchema = True
        elif opt in ('-p',"--path"):
            prettyprint = arg
        elif opt in ("-f", "--format"):
            if arg in ("pem", "der"):
                formatprint = arg
            else:
                print('请您输入{"pem","der"}中的一种')
                sys.exit(0)

def lint(file,formatprint):
    if formatprint == "pem":
        cert=x509.load_pem_x509_certificate(f.read(),default_backend())
    elif formatprint == "der":
        cert=x509.load_der_x509_certificate(f.read(),default_backend())
    try:
        zlintResult=zlint.LintCertificate(cert)
        print(json.dumps(zlintResult,indent =4,separators=(',', ': '),ensure_ascii=True,default=zlint.ResultSet.Tojson))
    except ValueError as e:
        print("sorry fatal error occured in the certificate!")
        print(f"the error message is : {str(e)} .")
        print("please try another one!")

def lint_once(file,base):
        try:
            cert=x509.load_pem_x509_certificate(file,default_backend())
            zlintResult=zlint.LintCertificate(cert)
            print(json.dumps(zlintResult,indent =4,separators=(',', ': '),ensure_ascii=True,default=zlint.ResultSet.Tojson))
            if(crl.CrlCheck().SplitUrl(cert,base)):
               print(crl.CrlCheck().SplitUrl(cert,base)) 
            else:
                print("the certificate had not been rovacated!")
        except:
            try:
                cert=x509.load_der_x509_certificate(file,default_backend())
                zlintResult=zlint.LintCertificate(cert)
                print(json.dumps(zlintResult,indent =4,separators=(',', ': '),ensure_ascii=True,default=zlint.ResultSet.Tojson))
                if(crl.CrlCheck().SplitUrl(cert,base)):
                    print(crl.CrlCheck().SplitUrl(cert,base)) 
                else:
                    print("the certificate had not been rovacated!")
            except ValueError as e:
                print("sorry fatal error occured in the certificate!")
                print(f"the error message is : {str(e)} .")
                print("please try another one!")

def check_online(file,base):
        try:
            cert=x509.load_pem_x509_certificate(file,default_backend())
            zlintResult=zlint.LintCertificate(cert)
            result = json.dumps(zlintResult,indent =4,separators=(',', ': '),ensure_ascii=True,default=zlint.ResultSet.Tojson)
            result = json.loads(result)
            if(crl.CrlCheck().SplitUrl(cert,base)):
                result['revoked'] =True
                #print(crl.CrlCheck().SplitUrl(cert,base)) 
            else:
                result['revoked'] = False 
                #print("the certificate had not been rovacated!")
            return result
        except:
            try:
                cert=x509.load_der_x509_certificate(file,default_backend())
                zlintResult = zlint.LintCertificate(cert)
                result = json.dumps(zlintResult,indent =4,separators=(',', ': '),ensure_ascii=True,default=zlint.ResultSet.Tojson)
                result = json.loads(result)
                if(crl.CrlCheck().SplitUrl(cert,base)):
                    result['revoked'] =True
                    #print(crl.CrlCheck().SplitUrl(cert,base)) 
                else:
                    result['revoked'] = False 
                    #print("the certificate had not been rovacated!")
                return result
            except ValueError as e:
                print("sorry fatal error occured in the certificate!")
                print(f"the error message is : {str(e)} .")
                print("please try another one!")
                return None

def init():
    currentdir = os.path.dirname(os.path.realpath(__file__))
    if os.name != 'nt':
        pkgpath = currentdir+'/lints'
    else:
        pkgpath = currentdir+'\lints'
    modules = [name for _, name, _ in pkgutil.iter_modules([pkgpath])]
    for module in modules:
        p = import_module(f"lints.{module}", __package__)
        if module=="base":
            continue
        p.init()        

def checkIt(cert):
    currentdir = os.path.dirname(os.path.realpath(__file__))
    base = currentdir+"\crls\\"
    return check_online(cert,base)
init()
if __name__ == '__main__':
    
    handleOption(sys.argv[1:])
    
    if listLintsJSON:
        zlint.EncodeLintDescriptionsToJSON()
        sys.exit(0)
    
    if listLintsSchema:
        names = []
        for lintName,_ in base.Lints.items():
            names.append(lintName)
        names.sort()
        print("Lints = SubRecord({")
        for name in names:
            print(f'   \"{ name }\":LintBool(),')
        print("})")
        print(f"There are {len(base.Lints)} rules in total.")
        sys.exit(0)

    if formatprint:
        flag = True
        while flag:
            filepath = input("please input the filepath which you want to test，and end with enter 0.\n")
            if filepath=="0":
                break
            try:
                with open(filepath,"rb") as f:  #本来是try下面的缩进块 但是得等开发完之后 加上try
                    lint(f,formatprint)
            except:
                print("sorry, cant't load the file! please enter the right path again!")


    if prettyprint:
        filepath = prettyprint
        if filepath=="0":
            sys.exit(0)
        try:
            with open(filepath,"rb") as f:  #本来是try下面的缩进块 但是得等开发完之后 加上try
                file = f.read()
                lint_once(file,currentdir+"\crls\\")
        except:
            print("sorry, cant't load the file! please enter the right path again!")