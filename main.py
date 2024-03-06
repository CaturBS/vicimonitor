import vici
from flask import Flask, session, request, render_template
from flask_session import Session
from flask_wtf import FlaskForm
from connection_form import ConnectionForm
import socket

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'


@app.route('/')
def index():
    conns = []
    try:
        conns = get_conns()
    except:
        return render_template('index.html', conns=None, fail="vici_fail")
    return render_template('index.html', conns=conns, fail="no")


@app.route('/create_connection')
def connection_form():
    form = ConnectionForm()
    if request.method == 'POST' and form.validate():
        form.get_dh_group_list()
    else:
        return render_template("create_connection.html", form=form)

@app.route('/get_conns', methods=['POST'])
def get_conns():
    sckt = socket.socket(socket.AF_UNIX)
    sckt.connect("/var/run/charon.vici")
    sess = vici.Session(sckt)
    conns_found = []
    for conn in sess.list_conns():
        conns_found.append(conn)
    return conns_found


if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    app.run("0.0.0.0", 5000)
