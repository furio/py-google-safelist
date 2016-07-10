from . import app, urlmanager, googleproc, tstore
from flask import request
from flask import jsonify
import base64
import urlhashes

# Routes definitions
@app.route("/")
def hello():
    return jsonify(**{"msg": "Hello to the google url malware checker. Call POST /url-check with {'url': 'your-url'}"})

@app.route("/url-hashes", methods = ["POST"])
def fetchurlhashes():
    jsonreq = request.get_json()
    
    if jsonreq is None:
        return jsonify(**{"error": "No url"})

    aurl = urlhashes.URL(jsonreq['url'])
    return jsonify(**{"hashes": [base64.b64encode(hashseg) for hashseg in aurl.hashes]})

@app.route("/url-check", methods = ["POST"])
def checkurlstatus():
    jsonreq = request.get_json()
    
    if jsonreq is None:
        return jsonify(**{"error": "No url"})

    aurl = urlmanager.isUrlBlocked(jsonreq['url'])
    return jsonify(**{"results": aurl})

@app.route("/shutdown", methods = ["GET"])
def shutdown():
    googleproc.stop()
    googleproc.waitforclose()
    tstore.close()

    return jsonify(**{"msg": "You can safely shutdown the server now"})