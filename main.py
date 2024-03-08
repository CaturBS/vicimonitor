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



@app.route('/create_connection', methods = ['POST','GET'])
def connection_form():
    form = ConnectionForm()

    if request.method == 'POST' and form.validate():
        new_conn_params = OrderedDict()
        the_conn = OrderedDict()
        new_conn_params[form.name.data] = the_conn
        the_conn['version'] = form.version.data
        the_conn['local_addrs'] = form.local_addrs.data
        the_conn['remote_addrs'] = form.remote_addrs.data
        the_conn['local_port'] = form.local_port.data
        the_conn['remote_port'] = form.remote_port.data
        the_conn['proposals'] = form.proposals.data
        the_conn['vips'] = form.vips.data
        the_conn['aggressive'] = form.aggressive.data
        the_conn['pull'] = form.pull.data
        if bool(form.dscp.data):
            the_conn['dscp'] = form.dscp.data
        the_conn['encap'] = form.encap.data
        if bool(form.dpd_delay.data):
            the_conn['dpd_delay'] = form.dpd_delay.data
        if bool(form.dpd_timeout.data):
            the_conn['dpd_timeout'] = form.dpd_timeout.data
        the_conn['fragmentation'] = form.fragmentation.data
        if bool(form.keyingtries.data):
            the_conn['keyingtries'] = form.keyingtries.data
        the_conn['unique'] = form.unique.data
        if bool(form.reauth_time.data):
            the_conn['reauth_time'] = form.reauth_time.data
        if bool(form.rekey_time.data):
            the_conn['rekey_time'] = form.rekey_time.data

        #local
        local_params = OrderedDict()
        the_conn['local'] = local_params

        if bool(form.local_round.data):
            local_params['round'] = form.local_round.data
        local_params['auth'] = form.local_auth.data
        local_params['id'] = form.local_id.data

        print('init form accept C (remote)')
        #remote
        remote_params = OrderedDict()
        the_conn['remote'] = remote_params
        if bool(form.remote_round.data):
            remote_params['round'] = form.remote_round.data
        remote_params['auth'] = form.remote_auth.data
        remote_params['id'] = form.remote_id.data


        #children
        children_params = OrderedDict()
        the_conn['children'] = children_params

        the_child_param = OrderedDict()
        children_params[form.children_name.data] = the_child_param
        the_child_param['esp_proposals'] = form.esp_proposals.data
        the_child_param['sha256_96'] = form.sha256_96.data
        the_child_param['local_ts'] = form.local_ts.data
        the_child_param['remote_ts'] = form.remote_ts.data
        if bool(form.child_rekey_time.data):
            the_child_param['rekey_time'] = form.child_rekey_time.data
        if bool(form.child_lifetime.data):
            the_child_param['lifetime'] = form.child_lifetime.data
        the_child_param['mode'] = form.child_mode.data
        the_child_param['policies'] = form.child_policies.data
        the_child_param['policies_fwd_out'] = form.child_policies_fwd_out.data
        the_child_param['dpd_action'] = form.dpd_action.data
        the_child_param['ipcomp'] = form.ipcomp.data
        if bool(form.child_inactivity.data):
            the_child_param['inactivity'] = form.child_inactivity.data
        if bool(form.child_reqid.data):
            the_child_param['reqid'] = form.child_reqid.data
        if bool(form.child_priority.data):
            the_child_param['priority'] = form.child_priority.data
        if bool(form.child_interface.data):
            the_child_param['interface'] = form.child_interface.data
        if bool(form.mark_in.data):
            the_child_param['mark_in'] = form.mark_in.data
        if bool(form.mark_in_sa.data):
            the_child_param['mark_in_sa'] = form.mark_in_sa.data
        if bool(form.mark_out.data):
            the_child_param['mark_out'] = form.mark_out.data
        if bool(form.set_mark_in.data):
            the_child_param['set_mark_in'] = form.set_mark_in.data
        if bool(form.set_mark_out.data):
            the_child_param['set_mark_out'] = form.set_mark_out.data
        if bool(form.if_id_in.data):
            the_child_param['if_id_in'] = form.if_id_in.data
        if bool(form.if_id_out.data):
            the_child_param['if_id_out'] = form.if_id_out.data
        if bool(form.child_label.data):
            the_child_param['label'] = form.child_label.data
        if bool(form.label_mode.data):
            the_child_param['label_mode'] = form.label_mode.data
        if bool(form.tfc_padding.data):
            the_child_param['tfc_padding'] = form.tfc_padding.data
        if bool(form.replay_window.data):
            the_child_param['replay_window'] = form.replay_window.data
        the_child_param['hw_offload'] = form.hw_offload.data
        the_child_param['copy_df'] = form.copy_df.data
        the_child_param['copy_ecn'] = form.copy_ecn.data
        the_child_param['copy_dscp'] = form.copy_dscp.data
        the_child_param['start_action'] = form.start_action.data
        the_child_param['close_action'] = form.close_action.data
        sess = ViciSess.get_sesssion()

        print(sess)
        sess.load_conn(new_conn_params)
        print(new_conn_params)

        conns_found = []
        for conn in sess.list_conns():
            conns_found.append(conn)
        # return conns_found
        return render_template('index.html', conns=conns_found, fail="no")

    elif request.method == 'POST':
        print(form.errors)
        return render_template("create_connection.html", form=form)
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
