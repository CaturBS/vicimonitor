import vici
from flask import Flask, session, request, render_template
from flask_session import Session
from flask_wtf import FlaskForm
from connection_form import ConnectionForm
from form.choose_encryption_form import ChooseEncryptionForm
import socket
from collections import OrderedDict
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'


@app.route('/')
def index():
    conns = []
    try:
        conns = get_conns()
        return render_template('index.html', conns=None, fail="vici_fail")
    except:
        return render_template('index.html', conns=None, fail="vici_fail")
    return render_template('index.html', conns=conns, fail="no")


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
    sckt = socket.socket(socket.AF_UNIX)
    sckt.connect("/var/run/charon.vici")
    sess = vici.Session(sckt)
    # conn_params = {
    #     'conn': "testcase",
    #     'local_addrs': "23.423.233.23",
    #     'remote_addrs': "233.32.23.87",
    #     'local': {
    #         'auth': 'psk',
    #         'id': 'your_local_id',
    #     },
    #     'remote': {
    #         'auth': 'psk',
    #         'id': 'your_remote_id'
    #     },
    #     'children': [{
    #         'name': 'child',
    #         'local_ts': '0.0.0.0/0',
    #         'remote_ts': '0.0.0.0/0',
    #         'start_action': 'start',
    #         'close_action': 'none',
    #         'esp_proposals': 'aes256gcm16-modp2048!'
    #     }],
    #     'ike': {
    #         'proposal': 'aes256gcm16-prfsha512-ecp384!',
    #         'lifetime': '1h',
    #         'encap': 'no',
    #         'auth_method': 'psk',
    #         'remote_auth': "dfdffd",
    #         'local_auth': "dfdfds"
    #     },
    #     'mark': 42,
    #     'keyingtries': 0,
    #     'reauth_time': 0
    # }
    #
    # # Load the connection configuration
    # sess.load_conn(conn_params)
    conns_found = []
    for conn in sess.list_conns():
        conns_found.append(conn)
    # return conns_found
    return render_template('index.html', conns=conns_found, fail="no")
@app.route('/home1')
def get_conns1():
    sckt = socket.socket(socket.AF_UNIX)
    sckt.connect("/var/run/charon.vici")
    sess = vici.Session(sckt)

    sa = OrderedDict()
    saconn = OrderedDict()
    sa["test"] = saconn
    saconn["local_addrs"] = "86.38.218.46"
    saconn["remote_addrs"] = "103.169.19.131"
    saconn["version"] = "1"
    saconn["proposals"] = "aes256-sha256-modp2048"
    local = OrderedDict()
    saconn["local"] = local
    local["auth"] = "psk"
    local["id"] = "86.38.218.46"
    remote = OrderedDict()
    saconn["remote"] = remote
    remote["auth"] = "psk"
    remote["id"] = "103.169.19.131"
    children = []
    saconn["children"] = children
    net2x = OrderedDict
    children["children"] = net2x
    net2x["local_ts"] = "192.168.42.0/24"
    net2x["remote_ts"] = "10.44.124.0/24"
    net2x["mode"] = "tunnel"
    # Load the connection configuration
    sess.load_conn(sa)
    conns_found = []
    for conn in sess.list_conns():
        conns_found.append(conn)
    # return conns_found
    return render_template('index.html', conns=conns_found, fail="no")

if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    app.run("0.0.0.0", 5001)
