import vici
from flask import Flask, session, request, render_template
from flask_session import Session
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/get_conns', methods=['POST'])
def get_conns():
    sess = vici.Session()
    sess.list_conns()

if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    app.run("0.0.0.0", 5000)