import vici
from flask import Flask, session, request, render_template
from flask_session import Session
import json

app = Flask(__name__)

@app.route('/')
def index():
    conns = []
    try:
        conns = get_conns()
    except:
        pass
    return render_template('index.html', conns=conns)


@app.route('/get_conns', methods=['POST'])
def get_conns():
    sess = vici.Session()
    conns_found = []
    for conn in sess.list_conns():
        conns_found.append(conn)
    return conns_found

if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    app.run("0.0.0.0", 5000)