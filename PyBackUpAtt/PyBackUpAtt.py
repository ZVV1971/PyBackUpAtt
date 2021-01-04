
from pykeepass import PyKeePass
import sys
import msvcrt
import json
from simple_salesforce import Salesforce
import requests
from html import escape
from threading import Thread
from queue import Queue

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
    kp = PyKeePass(kdbxpath, password=passw)
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

def main():
    creds, errs = provideCredentials()
    if len(errs) != 0:
        for k in errs:
            print(errs[k])
        print('Exiting... Press any key...')
        msvcrt.getch()
        sys.exit()

    #for k in creds:
        #print(creds[k])

    # manipulate the session instance (optional)
    sf = Salesforce(username=creds['UserName'], password=creds['Password'], security_token=creds['SecurityToken'], domain=creds['Domain'])

    data = sf.query_all("SELECT Id FROM {0}".format(creds['SalesForceObject']))
    q = Queue()

    for a in data['records']:
        q.put(a['Id'])

    for i in range(1,3):
        func = get_worker(creds['WorkMode'])
        Thread(target=func(q, sf, creds), daemon=True).start()
    q.join()


    print()

def get_worker(workmode):
    switcher={
        'Read':read_worker
        }
    return switcher.get(workmode, lambda *args:None)

def read_worker(q, sf, creds):
    while True:
            item = q.get()
            ##res = sf.query("SELECT Body FROM {0} WHERE id ='{1}'".format(creds['SalesForceObject'], item))
            res = sf.restful('{0}sobjects/{1}/{2}/Body'.format(sf.base_url, creds['SalesForceObject'], item))
            print('Got {0} from SalesForce'.format(item))
            
if __name__ == "__main__":
    main()