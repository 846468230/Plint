#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
import pkgutil
from importlib import import_module
import getopt
import sys
import zlint
from lints import base
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json

listLintsJSON = False
listLintsSchema = False
prettyprint = False
formatprint ="pem"


def Usage():
    print(
        "[Usage]:The option -j is listing the lints into JSON format.\n[Usage]:The option -s is listing Lints schema.\n[Usage]:The -p is listing Lints pretty.\n[Usage]:The -f is one of {pem,der}.\n[Usage]:Please use -h or -? for help.\n")


def handleOption(argv):
    global listLintsJSON
    global listLintsSchema
    global prettyprint
    global formatprint
    try:
        opts, args = getopt.getopt(argv, "jspf:h?", ["format="])
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
        elif opt == '-p':
            prettyprint = True
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
    #try:
    zlintResult=zlint.LintCertificate(cert)
    print(json.dumps(zlintResult,indent =4,separators=(',', ': '),ensure_ascii=True,default=zlint.ResultSet.Tojson))
    #except ValueError as e:
    #    print("sorry fatal error occured in the certificate!")
    #    print(f"the error message is : {str(e)} .")
    #    print("please try another one!")
    

if __name__ == '__main__':
    currentdir = os.path.dirname(os.path.realpath(__file__))
    pkgpath = currentdir+'\lints'
    modules = [name for _, name, _ in pkgutil.iter_modules([pkgpath])]
    for module in modules:
        p = import_module(f"lints.{module}", __package__)
        if module=="base":
            continue
        p.init()
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
        sys.exit(0)
    
    if formatprint:
        flag = True
        while flag:
            filepath = input("please input the filepath which you want to test，and end with enter 0.\n")
            if filepath=="0":
                break
            #try:
            with open(filepath,"rb") as f:  #本来是try下面的缩进块 但是得等开发完之后 加上try
                lint(f,formatprint)
            #except:
            #    print("sorry, cant't load the file! please enter the right path again!")


