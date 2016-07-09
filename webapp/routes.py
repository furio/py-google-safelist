from . import app, tstore, rediscli
from flask import request
from flask import jsonify
import base64
import urlhashes

# Routes definitions
@app.route("/")
def hello():
    return "Hello World!"

@app.route("/url-hashes", methods = ["POST"])
def fetchurlhashes():
    jsonreq = request.get_json()
    
    if jsonreq is None:
        return jsonify(**{"error": "No url"})

    aurl = urlhashes.URL(jsonreq['url'])
    return jsonify(**{"hashes": [base64.b64encode(hashseg) for hashseg in aurl.hashes]})