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

def provideCredentials():

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
        passw +=x.decode('utf-8')

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
        'Read':read_worker
        }
    return switcher.get(workmode, lambda *args:None)

def read_worker():
    while True:
            item = q.get()
            ## Have to use direct request since simple-salesforce restful functionallity fails to get binary content
            res = requests.get('{0}sobjects/{1}/{2}/Body'.format(sf.base_url, creds['SalesForceObject'], item), 
                               headers={'Authorization':'Bearer {0}'.format(sf.session_id)})
            print('Got {0} from SalesForce; {1} bytes at {2} from {3}'.format(item, len(res.content), datetime.now(), threading.currentThread().getName()))
            
            creds['ResultsFile'].write('{0},{1}'.format(item, b64encode(creds['Cipher'].encrypt(pad(res.content, AES.block_size))).decode('utf-8')))
            q.task_done()

def prepare_crypto_stuf(creds):
    kdf = PBKDF2(creds['AESPassword'], creds['Salt'])
    creds['Cipher'] = AES.new(kdf, AES.MODE_CBC, b64decode(creds['IV']))

creds, errs = provideCredentials()
q = Queue()

prepare_crypto_stuf(creds)

# manipulate the session instance (optional)
sf = Salesforce(username=creds['UserName'], password=creds['Password'], security_token=creds['SecurityToken'], domain=creds['Domain'])

def main():
    if len(errs) != 0:
        for k in errs:
            print(errs[k])
        print('Exiting... Press any key...')
        msvcrt.getch()
        sys.exit()
    
    data = sf.query_all("SELECT Id FROM {0}".format(creds['SalesForceObject']))

    for a in data["records"]:
        q.put(a["Id"])

    with open("results.dat",'a', 1) as f:
        creds['ResultsFile'] = f
        for i in range(creds["NumberOfThreads"]):
            func = get_worker(creds['WorkMode'])
            t = threading.Thread(target=func, daemon=True)
            t.start()
            print("Thread {0} has been started".format(t.getName()))
        #wait till all rows are processed then close the result file
        q.join()
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