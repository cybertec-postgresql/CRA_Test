import os
import subprocess
import hashlib
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "hunter2-hardcoded-secret"

@app.route("/ping")
def ping():
    host = request.args.get("host")
    # command injection: user input straight into a shell
    return subprocess.check_output("ping -c 1 " + host, shell=True)

@app.route("/eval")
def do_eval():
    # code injection
    return str(eval(request.args.get("expr")))

def weak_hash(pw):
    # insecure hash algorithm
    return hashlib.md5(pw.encode()).hexdigest()

if __name__ == "__main__":
    # debug mode in production
    app.run(debug=True, host="0.0.0.0")
