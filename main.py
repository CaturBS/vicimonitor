import vici
from flask import Flask, session, request, render_template
from flask_session import Session
from flask_wtf import FlaskForm
from connection_form import ConnectionForm
from form.choose_encryption_form import ChooseEncryptionForm
import json
import socket
from collections import OrderedDict
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'


class ViciSess:
    vicisession = None
    @staticmethod
    def get_sesssion():
        if ViciSess.vicisession is None:
            ViciSess.vicisession = vici.Session()
        return ViciSess.vicisession
    
@app.route('/')
def index():
    try:
        sess = ViciSess.get_sesssion()
        conns_found = []
        for conn in sess.list_conns():
            conns_found.append(conn)
        return render_template('index.html', conns=conns_found, fail="no")
    except:
        return render_template('index.html', conns=None, fail="vici_fail")


@app.route('/create_encyrpt/<idx>')
def create_encyrpt_form(idx):
    form = ChooseEncryptionForm(str(idx))
    return render_template("choose_encryption.html", form=form)
@app.route('/create_connection')
def connection_form():
    form = ConnectionForm()
    if request.method == 'POST' and form.validate():
        form.name
    else:
        return render_template("create_connection.html", form=form)

@app.route('/home')
def get_conns():
    sess = ViciSess.get_sesssion()
    conns_found = []
    for conn in sess.list_conns():
        conns_found.append(conn)
    # return conns_found
    return render_template('index.html', conns=conns_found, fail="no")

def get_conns1():
    sess = ViciSess.get_sesssion()

    conn_params = {
        'test_vpn': {
            'local_addrs': ['88.2.3.1'],
            'remote_addrs': ['23.32.2.3'],
            'version': 1,
            'proposals': ['aes256-sha256-modp2048'],
            'rekey_time': 86400,
            'fragmentation': 'yes',
            'local': {
                'auth': 'psk',
                'id': '86.38.218.46'
            },
            'remote': {
                'auth': 'psk',
                'id': '103.169.19.131'
            },
            'children': {
                'testchild': {
                    'local_ts': ['192.168.42.0/24'],
                    'remote_ts': ['10.144.124.0/24'],
                    'mode': 'tunnel',
                    'rekey_time': '3600',
                    'esp_proposals': ['aes256-sha256'],
                    'start_action': 'start'
                }
            }
        }
    }
    # Load the connection configuration
    sess.load_conn(conn_params)
    conns_found = []
    for conn in sess.list_conns():
        conns_found.append(conn)
    # return conns_found
    return render_template('index.html', conns=conns_found, fail="no")

if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    app.run("0.0.0.0", 5001)
