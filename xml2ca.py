#!/usr/bin/python2
#coding: UTF8
import xml.etree.ElementTree as ET
import base64 as b
import requests
import sys
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import CRLDistributionPoints
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import hashlib
import ldap
import urlparse
import urllib
import pymongo
import gridfs
import logging
from logging.handlers import  TimedRotatingFileHandler
import Queue
import threading
import config

N_THREADS=config.N_THREADS
MONGO=config.MONGO

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.propagate=False
formatter=logging.Formatter('%(asctime)s#%(levelname)s#%(name)s#%(threadName)s#%(message)s')
handler=TimedRotatingFileHandler(filename=config.LOG_FILE,when='D',backupCount=30)
handler.setFormatter(formatter)
log.addHandler(handler)
#handler=logging.StreamHandler()
#handler.setFormatter(formatter)
#handler.setLevel(logging.INFO)
#log.addHandler(handler)


EU_CA_URL="https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml"
EU_RENEW_XPATH="./{http://uri.etsi.org/02231/v2#}SchemeInformation/{http://uri.etsi.org/02231/v2#}NextUpdate/{http://uri.etsi.org/02231/v2#}dateTime"
#CA_URL="https://eidas.agid.gov.it/TL/TSL-IT.xml"
IT_CA_XPATH=".//{http://uri.etsi.org/02231/v2#}OtherInformation[{http://uri.etsi.org/02231/v2#}SchemeTerritory='IT']/../../{http://uri.etsi.org/02231/v2#}TSLLocation"



class Mongola(object):
    def __init__(self,conf):
        self.conn=pymongo.MongoClient(conf['uri'])
        self.db=self.conn[conf['db']]
        self.gfs=gridfs.GridFS(self.db)

    def find_one(self,filter):
        res=self.db.fs.files.find_one(filter)
        if res:
            return self.gfs.get(res['_id'])
        return None

def cert2hash(cert):
    key=cert.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
    sha=hashlib.sha1()
    sha.update(key)
    return sha.hexdigest()

def get_it_ca_from_eu_ca(m,url=EU_CA_URL,save_path="tl-mp.xml"):
    log.debug("Getting EU XML file")
    f = m.find_one({"filename": save_path})
    if f:
        doc=ET.fromstring(f.read())
        next_update = datetime.datetime.strptime(doc.findall(EU_RENEW_XPATH)[0].text, '%Y-%m-%dT%H:%M:%SZ')
        if datetime.datetime.utcnow() <= next_update:
            return (doc.findall(IT_CA_XPATH)[0].text, False)
    res=requests.get(url)
    if f:
        m.gfs.delete(f._id)
    m.gfs.put(res.content,filename=save_path)
    doc = ET.fromstring(res.content)
    return (doc.findall(IT_CA_XPATH)[0].text,True)

def get_it_ca_list(m,url,save_path="TSL-IT.xml",force_download=False):
    log.debug("Getting IT XML file")
    f = m.find_one({"filename": save_path})
    if not force_download:
        if f:
            doc = ET.fromstring(f.read())
            next_update = datetime.datetime.strptime(doc.findall(EU_RENEW_XPATH)[0].text, '%Y-%m-%dT%H:%M:%SZ')
            if datetime.datetime.utcnow() <= next_update:
                return (doc, False)
    res=requests.get(url)
    if f:
        m.gfs.delete(f._id)
    m.gfs.put(res.content, filename=save_path)
    doc = ET.fromstring(res.content)
    return (doc,True)

def is_crl_expired(crl_data):
    try:
        crl=x509.load_der_x509_crl(crl_data,default_backend())
    except:
        try:
            crl=x509.load_pem_x509_crl(crl_data,default_backend())
        except:
            raise Exception ("Impossibile aprire la crl")
    #Scarichiamo se siamo a meno di 2 giorni dal prossimo update
    if crl.next_update < datetime.datetime.utcnow()+datetime.timedelta(days=1):
        return True
    return False

def ldap_get_crl(uri,crl_filename,m):
    log.debug("Getting crl via ldap %s filename: %s ",uri,crl_filename)
    f = m.find_one({"filename": crl_filename})
    if f:
        log.debug("crl already present")
        data = f.read()
        f.close()
        if not is_crl_expired(data):
            log.debug("crl was NOT expired")
            return data
        log.debug("crl was expired")
    p=urlparse.urlparse(uri)
    log.debug(p.netloc)
    l=ldap.initialize(uri=p.scheme+"://"+p.netloc)
    l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    l.set_option(ldap.OPT_NETWORK_TIMEOUT,5)
    log.debug(urllib.unquote(p.path).lstrip('/'))
    res=l.search_s(urllib.unquote(p.path).lstrip('/'),ldap.SCOPE_BASE)
    l.unbind_s()
    for r in res:
        if r[1].get(p.query):
            crl= r[1][p.query][0]
        elif r[1].get(p.query+";binary"):
            crl= r[1][p.query+";binary"][0]
        else:
            raise Exception("Impossibile scaricare crl da %s"%uri)
    if f:
        log.debug("CANCELLO: %s" % str(f._id))
        m.gfs.delete(f._id)
    m.gfs.put(crl,filename=crl_filename)
    return crl

def http_get_crl(uri,crl_filename,m):
   # try:
   #     with open(crl_path,'r') as f:
   #        doc=f.read()
   #    if not is_crl_expired(doc):
   #        return doc
   #except IOError,e:
   #    if e.errno!=2: #file non esiste
   #        raise
    log.debug("Getting crl via http %s filename: %s ", uri, crl_filename)
    f=m.find_one({"filename":crl_filename})
    if f:
        log.debug("crl already present")
        data=f.read()
        f.close()
        if not is_crl_expired(data):
            log.debug("crl was NOT expired")
            return data
        log.debug("crl was expired")
    res= requests.get(uri,timeout=5,verify=False)
    if f:
        m.gfs.delete(f._id)
        log.debug("CANCELLO: %s"%str(f._id))
    m.gfs.put(res.content,filename=crl_filename)
    return res.content

def download_worker(m):

    while True:
        try:
            cert = CERT_QUEUE.get_nowait()
        except Queue.Empty:
            return
        try:
            derdata = b.b64decode(cert.text)
            xcert = x509.load_der_x509_certificate(derdata, default_backend())
            subject_name = '.'.join([x.value for x in xcert.subject])
            if xcert.not_valid_after < datetime.datetime.utcnow():
                continue
            filename = cert2hash(xcert)
            cert_filename = filename + ".crt"
            crl_filename = filename + ".crl"
            log.debug(subject_name)
            # crt_path=os.path.join(OUT_DIR, "%s.crt" % subject_name.replace('/', '_'))
            # crl_path=os.path.join(OUT_DIR, "%s.crl" % subject_name.replace('/', '_'))
            try:
                m.gfs.put(derdata, filename=cert_filename, metadata={'subject_name': subject_name})
            except gridfs.errors.FileExists:
                # Ce l'abbiamo già
                pass
                # with open(crt_path, 'w') as f:
                #     f.write(derdata)
            ext = xcert.extensions.get_extension_for_oid(CRLDistributionPoints.oid)
            for c in ext.value:
                for d in c.full_name:
                    if type(d.value) == type(u'') and d.value.startswith('http'):
                        # print d.value
                        try:
                            crl = http_get_crl(d.value, crl_filename, m)
                        except requests.exceptions.Timeout:
                            log.error("Timeout scaricando: %s" % d.value)
                    elif type(d.value) == type(u'') and d.value.startswith('ldap'):
                        # print d.value
                        try:
                            crl = ldap_get_crl(d.value, crl_filename, m)
                        except:
                            log.error("Problemi a scaricare la crl per: %s" % d.value)
                    else:
                        pass
                        # print "VALUE STRAMBO: %s"%d.value

        except Exception, e:
            # raise
            log.error("ERRORE: %s su cert %s " % (e, xcert.issuer))
        finally:
            CERT_QUEUE.task_done()


def download_ca(doc,m):
    i = 0
    host_set = set()
    for cert in doc.findall(".//{http://uri.etsi.org/02231/v2#}X509Certificate"):
        CERT_QUEUE.put(cert)
    threads=[]
    log.info("Starting threads")
    for n in xrange(N_THREADS):
        t=threading.Thread(target=download_worker,args=(m,))
        threads.append(t)
        t.start()
    log.info("Waiting for threads to finish")
    CERT_QUEUE.join()
    log.info("Threads done")



CERT_QUEUE=Queue.Queue()
def store_and_download(uri,hash):
    m=Mongola(MONGO)
    urls=m.db['other_urls']
    urls.create_index('uri',unique=True)
    res=urls.find({'uri':uri})
    crl_filename=hash+'.crl'
    if  res.count()==0:
        urls.insert({'uri':uri,'hash':hash},j=True)
    if uri.startswith('http'):
        crl=http_get_crl(uri,crl_filename,m)
    elif uri.startswith('ldap'):
        crl = ldap_get_crl(uri, crl_filename, m)
    else:
        raise Exception("uri scheme not supported")

if __name__=='__main__':
    #uri="ldap://certificati.postecert.it:389/CN=Provincia%20Autonoma%20di%20Bolzano%20-%20CA%20Cittadini,OU%3dServizi%20di%20Certificazione,O%3dPoste%20Italiane%20S.p.A.,C%3dIT?certificateRevocationList"
    #ldap_get_crl(uri,"/tmp/sfasd")
    log.info("Starting CRL download")
    #sys.exit(0)
    m=Mongola(MONGO)
    it_url=get_it_ca_from_eu_ca(m)
    res=get_it_ca_list(m,it_url[0],force_download=it_url[1])
    download_ca(res[0],m)
    log.info("Downloading additional CRL")
    urls=m.db['other_urls']
    res=urls.find()
    for r in res:
        store_and_download(r['uri'],r['hash'])
    log.info("CRL download END")
    sys.exit(0)



