import vici
from flask import Flask, session, request, render_template
# from flask_session import Session
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
        new_conn_params = OrderedDict()
        the_conn = OrderedDict()
        new_conn_params[form.name] = the_conn
        the_conn['version'] = int(form.version)
        the_conn['local_addrs'] = form.local_addrs
        the_conn['remote_addrs'] = form.remote_addrs
        the_conn['local_port'] = form.local_port
        the_conn['remote_port'] = form.remote_port
        the_conn['proposals'] = form.proposals
        the_conn['vips'] = form.vips
        the_conn['aggressive'] = form.aggressive
        the_conn['pull'] = form.pull
        if bool(form.dscp and form.dscp.strip()):
            the_conn['dscp'] = form.dscp
        the_conn['encap'] = form.encap
        if bool(form.dpd_delay and form.dpd_delay.strip()):
            the_conn['dpd_delay'] = form.dpd_delay
        if bool(form.dpd_timeout and form.dpd_timeout.strip()):
            the_conn['dpd_timeout'] = form.dpd_timeout
        the_conn['fragmentation'] = form.fragmentation
        if bool(form.keyingtries and form.keyingtries.strip()):
            the_conn['keyingtries'] = form.keyingtries
        the_conn['unique'] = form.unique
        if bool(form.reauth_time and form.reauth_time.strip()):
            the_conn['reauth_time'] = form.reauth_time
        if bool(form.rekey_time and form.rekey_time.strip()):
            the_conn['rekey_time'] = form.rekey_time

        #local
        local_params = OrderedDict()
        the_conn['local'] = local_params

        if bool(form.local_round and form.local_round.strip()):
            local_params['local_round'] = int(form.local_round)
        local_params['auth'] = form.local_auth
        local_params['id'] = form.local_id

        #remote
        remote_params = OrderedDict()
        the_conn['remote'] = remote_params
        if bool(form.remote_round and form.remote_round.strip()):
            remote_params['remote_round'] = int(form.remote_round)
        remote_params['auth'] = form.remote_auth
        remote_params['id'] = form.remote_id


        #remote
        children_params = OrderedDict()
        the_conn['children'] = children_params

        the_child_param = OrderedDict()
        children_params[form.children_name] = the_child_param
        the_child_param['esp_proposals'] = form.esp_proposals
        the_child_param['sha256_96'] = form.sha256_96
        the_child_param['local_ts'] = form.local_ts
        the_child_param['remote_ts'] = form.remote_ts
        if bool(form.child_rekey_time and form.child_rekey_time.strip()):
            the_child_param['rekey_time'] = form.child_rekey_time
        if bool(form.child_lifetime and form.child_lifetime.strip()):
            the_child_param['lifetime'] = form.child_lifetime
        the_child_param['mode'] = form.child_mode
        the_child_param['policies'] = form.child_policies
        the_child_param['policies_fwd_out'] = form.child_policies_fwd_out
        the_child_param['dpd_action'] = form.dpd_action
        the_child_param['ipcomp'] = form.ipcomp
        if bool(form.child_inactivity and form.child_inactivity.strip()):
            the_child_param['inactivity'] = form.child_inactivity
        if bool(form.child_reqid and form.child_reqid.strip()):
            the_child_param['reqid'] = form.child_reqid
        if bool(form.child_priority and form.child_priority.strip()):
            the_child_param['priority'] = form.child_priority
        if bool(form.child_interface and form.child_interface.strip()):
            the_child_param['interface'] = form.child_interface
        if bool(form.mark_in and form.mark_in.strip()):
            the_child_param['mark_in'] = form.mark_in
        if bool(form.mark_in_sa and form.mark_in_sa.strip()):
            the_child_param['mark_in_sa'] = form.mark_in_sa
        if bool(form.mark_out and form.mark_out.strip()):
            the_child_param['mark_out'] = form.mark_out
        if bool(form.set_mark_in and form.set_mark_in.strip()):
            the_child_param['set_mark_in'] = form.set_mark_in
        if bool(form.set_mark_out and form.set_mark_out.strip()):
            the_child_param['set_mark_out'] = form.set_mark_out
        if bool(form.if_id_in and form.if_id_in.strip()):
            the_child_param['if_id_in'] = form.if_id_in
        if bool(form.if_id_out and form.if_id_out.strip()):
            the_child_param['if_id_out'] = form.if_id_out
        if bool(form.child_label and form.child_label.strip()):
            the_child_param['label'] = form.child_label
        if bool(form.label_mode and form.label_mode.strip()):
            the_child_param['label_mode'] = form.label_mode
        if bool(form.tfc_padding and form.tfc_padding.strip()):
            the_child_param['tfc_padding'] = form.tfc_padding
        if bool(form.replay_window and form.replay_window.strip()):
            the_child_param['replay_window'] = form.replay_window
        the_child_param['hw_offload'] = form.hw_offload
        the_child_param['copy_df'] = form.copy_df
        the_child_param['copy_ecn'] = form.copy_ecn
        the_child_param['copy_dscp'] = form.copy_dscp
        the_child_param['start_action'] = form.start_action
        the_child_param['close_action'] = form.close_action
        sess = ViciSess.get_sesssion()
        sess.load_conn(new_conn_params)

        conns_found = []
        for conn in sess.list_conns():
            conns_found.append(conn)
        # return conns_found
        return render_template('index.html', conns=conns_found, fail="no")


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
    # Session(app)
    app.run("0.0.0.0", 5001)
