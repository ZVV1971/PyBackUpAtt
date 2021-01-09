from pykeepass import PyKeePass
from pykeepass.exceptions import *
import sys
import os
import msvcrt
import json
from simple_salesforce import Salesforce
from html import escape
import threading
from queue import Queue
import requests
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from base64 import b64decode
from base64 import b64encode
from Cryptodome.Util.Padding import pad, unpad

creds=[]

def provideCredentials():
    global creds
    kdbxpath=''
    grp=''
    entr=''
    errs = {}
    #dictionary to return
    creds = dict.fromkeys(['UserName', 'Password', 'AESPassword', 'IV', 'Salt', 'SecurityToken'])

    #read config
    try:
        with open('config.json') as json_file:
            data = json.load(json_file)
            kdbxpath = data['KDBXPath']
            grp = data["GroupName"]
            entr = data["EntryName"]
            creds["Domain"] = data ["Domain"]
            creds["SalesForceObject"] = data["SalesForceObject"]
            creds["WorkMode"] = data["WorkMode"]
            creds["NumberOfThreads"] = data["NumberOfThreads"]
            creds["ResultsFileName"] = data["ResultsFileName"]
            creds["ComparisonResultsFileName"] = data["ComparisonResultsFileName"]
    except OSError:
        errs['config_file'] = 'Error opening configuration file'
        return dict, errs
    except KeyError as kerr:
        errs['config_keys'] = 'Necessary entry {0} is not found in the config file'.format(kerr)
        return dict, errs

    #get password
    for c in 'Please, enter the password:':
        msvcrt.putch(c.encode('utf-8'))
    passw = ''
    while True:
        x = msvcrt.getch()
        if x == b'\r':
            print('')
            break
        elif x == b'\b':
            passw = passw[:-1]
            continue
        msvcrt.putch(b'*')
        passw +=x.decode('cp866')

    # load database and find entry
    try:
        kp = PyKeePass(kdbxpath, password=passw)
    except CredentialsError as cer:
        print("Incorrect credentials {0}".format(cer))
        exit(-2)

    for gr in kp.groups:
        if gr.name == grp:
            for en in gr.entries:
                if en.title == entr:
                    try:
                        creds['UserName'] = en.username
                        creds['Password'] = en.password
                        creds['AESPassword'] = en.custom_properties['AESpassword']
                        creds['IV'] = en.custom_properties['IV']
                        creds['Salt'] = en.custom_properties['Salt']
                        creds['SecurityToken'] = en.custom_properties['SecurityToken']
                    except KeyError as kerr:
                        errs['kdbxentry'] = 'Necessary entry {0} is not found in the KDBX database file'.format(kerr)
                        return creds, errs
    return creds, errs

def get_worker(workmode):
    switcher={
        'Read':read_worker,
        'Compare':compare_worker
        }
    return switcher.get(workmode, lambda *args:None)

def get_preparator(workmode):
    switcher={
        'Read':prepare_reader,
        'Compare':prepare_comparator
        }
    return switcher.get(workmode, lambda *args:None)

def read_worker():
    global creds
    while True:
        item = creds["working_queue"].get()
        ## Have to use direct request since simple-salesforce restful functionallity fails to get binary content
        res = requests.get('{0}sobjects/{1}/{2}/Body'.format(creds["SFSession"].base_url, creds['SalesForceObject'], item), 
                               headers={'Authorization':'Bearer {0}'.format(creds["SFSession"].session_id)})
        print('Got {0} from SalesForce; {1} bytes at {2} from {3}'.format(item, len(res.content), datetime.now(), threading.currentThread().getName()))
            
        creds['ResultsFile'].write('{0},{1}{2}'.format(item, b64encode(creds['Cipher'].encrypt(pad(res.content, AES.block_size))).decode('utf-8'),'\r'))
        creds["working_queue"].task_done()

def compare_worker():
    global creds
    while True:
        item = creds["working_queue"].get()
        id, body = item.split(',')
        ## Have to use direct request since simple-salesforce restful functionallity fails to get binary content
        res = requests.get('{0}sobjects/{1}/{2}/Body'.format(creds["SFSession"].base_url, creds['SalesForceObject'], id), 
                               headers={'Authorization':'Bearer {0}'.format(creds["SFSession"].session_id)})
        print('Got {0} from SalesForce; {1} bytes at {2} from {3}'.format(item, len(res.content), datetime.now(), threading.currentThread().getName()))
            
        creds['ComparisonResultsFile'].write('{0},{1}{2}'.format(item, b64encode(creds['Cipher'].encrypt(pad(res.content, AES.block_size))).decode('utf-8') == body,'\r'))
        creds["working_queue"].task_done()
        

def prepare_crypto_stuf(creds):
    kdf = PBKDF2(creds['AESPassword'], creds['Salt'])
    creds['Cipher'] = AES.new(kdf, AES.MODE_CBC, b64decode(creds['IV']))

def prepare_reader():
    global creds
    data = creds["SFSession"].query_all("SELECT Id FROM {0}".format(creds['SalesForceObject']))
    for a in data["records"]:
        creds["working_queue"].put_nowait(a["Id"])

def prepare_comparator():
    global creds
    pass

def main():
    global creds
    creds, errs = provideCredentials()

    if len(errs) != 0:
        for k in errs:
            print(errs[k])
        print('Exiting... Press any key...')
        msvcrt.getch()
        sys.exit()
    
    
    creds["working_queue"] = Queue()

    prepare_crypto_stuf(creds)

    creds["SFSession"] = Salesforce(username=creds['UserName'], password=creds['Password'], security_token=creds['SecurityToken'], domain=creds['Domain'])
    
    get_preparator(creds["WorkMode"])()

    with open(creds["ResultsFileName"],"a+", 1) as f, open(creds["ComparisonResultsFileName"],"a+",1) as c:
        creds['ResultsFile'] = f
        creds['ComparisonResultsFile'] = c
        for i in range(creds["NumberOfThreads"]):
            func = get_worker(creds['WorkMode'])
            t = threading.Thread(target=func, daemon=True)
            t.start()
            print("Thread {0} has been started".format(t.getName()))
        #wait till all rows are processed then close the result file
        creds["working_queue"].join()
    print()

if __name__ == "__main__":
    main()

class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)