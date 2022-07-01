import os
#os.environ['http_proxy']="http://proxypal:8080"
#os.environ['https_proxy']="http://proxypal:8080"

N_THREADS=10

MONGO={
       'uri':'mongodb://localhost/crl',
       'db':'crl'
       }

LOG_FILE="crl_downloader.log"

try:
    os.makedirs(os.path.dirname(LOG_FILE),0755)
except OSError, e:
    if e.errno==17:
        pass