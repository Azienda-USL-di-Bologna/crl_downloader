from bottle import  app,get,request,HTTPError,run
import sys
import os
import json
sys.path.append(os.path.dirname(__file__))
import xml2ca

_TOKEN='XEuwuMKYnqGX8CDkPbLMnMHj'



@get('/')
def get_crl():
    uri=request.params.get('uri')
    hash=request.params.get('hash')
    token=request.params.get('token')
    if not all((uri,hash,request)):
        raise HTTPError(400,'manca un parametro')
    if token!=_TOKEN:
        raise HTTPError(401,'token errato')
    uri=json.loads(uri)
    xml2ca.store_and_download(uri[0],hash)
    return "crl downloaded"


if __name__=='__main__':
    run(app(),host='0.0.0.0',reloader=True)
else:
    os.chdir(os.path.dirname(__file__))
    application=app()

