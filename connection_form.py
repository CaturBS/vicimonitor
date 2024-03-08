import os

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField
from wtforms.validators import InputRequired, IPAddress, Optional, Regexp


class ConnectionForm(FlaskForm):

    @staticmethod
    def get_dh_group_list() -> list:
        path = os.path.join(os.getcwd(), "encryptionlist", "dhgroups.txt")
        lines = []
        with open(path) as file:
            for line in file:
                line = line.strip()
                lines.append(line)
        return lines

    @staticmethod
    def get_integrity_list() -> list:
        path = os.path.join(os.getcwd(), "encryptionlist", "integrity.txt")
        lines = []
        with open(path) as file:
            for line in file:
                line = line.strip()
                lines.append(line)
        return lines

    @staticmethod
    def get_encryption_list() -> list:
        path = os.path.join(os.getcwd(), "encryptionlist", "encryption.txt")
        lines = []
        with open(path) as file:
            for line in file:
                line = line.strip()
                lines.append(line)
        return lines

    name = StringField('Connection Name', name="name", validators=[InputRequired()])
    local_addrs = StringField('Local Addresses', name="local_addrs", validators=[InputRequired(), IPAddress()])
    remote_addrs = StringField('Remote Addresses', name="remote_addrs")
    version = SelectField(label='IKE Version', name='version', choices=["1"])
    local_port = StringField('Local Port', name="local_port",
                             validators=[Optional(), Regexp(r'^\d{1,5}$', message="Invalid port number")])
    remote_port = StringField('Local Port', name="remote_port",
                              validators=[Optional(), Regexp(r'^\d{1,5}$', message="Invalid port number")])
    proposals = StringField('Proposals (IKE)', name="proposals", validators=[InputRequired()])
    vips = StringField('Vips', name="vips", validators=[Optional(), IPAddress()])
    aggressive = SelectField(label='Aggressive', name='aggressive', choices=["no", "yes"])
    pull = SelectField(label='Pull', name='pull', choices=["yes", "no"])
    dscp = StringField('DSCP', name="local_port",
                       validators=[Optional(), Regexp(r'^\d{6}$', message="Invalid DSCP format, should 6 digit")])
    encap = SelectField(label='Encap', name='encap', choices=["no", "yes"])
    dpd_delay = StringField('Dpd Delay(default 0s)', name="dpd_delay", validators=[Optional(), Regexp(r'^\d+[smh]')])
    dpd_timeout = StringField('Dpd Timeout(default 0s)', name="dpd_timeout",
                              validators=[Optional(), Regexp(r'^\d+[smh]')])
    fragmentation = SelectField(label='fragmentation', name='fragmentation', choices=["yes", "accept", "force", "no"])
    keyingtries = StringField('keyingtries (default 1)', name="keyingtries",
                              validators=[Optional(), Regexp(r'^\d+$', message="Should be integer")])
    unique = SelectField(label='unique', name='unique', choices=["no", "never", "replace", "keep"])
    reauth_time = StringField('reauth_time (default 0s)', name="reauth_time",
                              validators=[Optional(), Regexp(r'^\d+[smh]')])
    rekey_time = StringField('rekey_time (default 0s)', name="rekey_time",
                             validators=[Optional(), Regexp(r'^\d+[smh]')])
    over_time = StringField('over_time (default 0s)', name="over_time",
                            validators=[Optional(), Regexp(r'^\d+[smh]')])

    # local auth
    local_round = StringField('round', name="local_round",
                        validators=[Optional(), Regexp(r'^\d+$', message="should be number")])
    local_auth = SelectField(label='auth', name='local_auth', choices=["psk"])
    local_secret = StringField('local_secret', name='local_secret');
    local_id = StringField('ID', name="local_id",
                            validators=[Optional()])

    # remote auth
    remote_round = StringField('round', name="remote_round",
                        validators=[Optional(), Regexp(r'^\d+$', message="should be number")])
    remote_auth = SelectField(label='auth', name='remote_auth', choices=["psk"])
    remote_id = StringField('ID', name="remote_id",
                            validators=[Optional()])
    remote_secret = StringField('local_secret', name='remote_secret');


    # children
    children_name = StringField('children_name', name="children_name", validators=[InputRequired()])
    esp_proposals = StringField('esp_proposals', name="esp_proposals")
    sha256_96 = SelectField(label='sha256_96', name='sha256_96', choices=["no", "yes"])
    local_ts = StringField('local_ts', name="local_ts", validators=[InputRequired()])
    remote_ts = StringField('remote_ts', name="remote_ts", validators=[InputRequired()])

    child_rekey_time = StringField('rekey_time (for child, default 1h)', name="child_rekey_time",
                             validators=[Optional(), Regexp(r'^\d+[smh]')])

    child_lifetime = StringField('lifetime', name="child_lifetime")

    child_mode = SelectField(label='mode', name='child_mode', choices=["tunnel", "transport", " transport_proxy"," beet"," pass"," drop"])
    child_policies = SelectField(label='policie', name='child_policies', choices=["yes","no"])
    child_policies_fwd_out = SelectField(label='policies_fwd_out', name='child_policies_fwd_out', choices=["no","yes"])
    dpd_action = SelectField(label='dpd_action', name='dpd_action', choices=["clear", "trap"])
    ipcomp = SelectField(label='ipcomp', name='ipcomp', choices=["no", "yes"])
    child_inactivity = StringField('inactivity (default 0s)', name="child_inactivity", validators=[Optional(), Regexp(r'^\d+[smh]$')])
    child_reqid = StringField('reqid (default 0)', name="child_reqid", validators=[Optional(), Regexp(r'^\d+$')])
    child_priority = StringField('priority (default 0)', name="child_priority", validators=[Optional(), Regexp(r'^\d+$')])
    child_interface = StringField('interface', name="child_interface", validators=[Optional()])
    mark_in = StringField('mark_in', name="mark_in", validators=[Optional()])
    mark_in_sa = SelectField(label='mark_in_sa', name='mark_in_sa', choices=["no", "yes"])
    mark_out = StringField('mark_out', name="mark_out", validators=[Optional()])
    set_mark_in = StringField('set_mark_in', name="set_mark_in", validators=[Optional()])
    set_mark_out = StringField('set_mark_out', name="set_mark_out", validators=[Optional()])
    if_id_in = StringField('if_id_in', name="if_id_in", validators=[Optional()])
    if_id_out = StringField('if_id_out', name="if_id_out", validators=[Optional()])
    child_label = StringField('label', name="child_label", validators=[Optional()])
    label_mode = SelectField(label='label_mode', name='label_mode', choices=["system", "selinux", " simple"])
    tfc_padding = StringField('tfc_padding (default 0)', name="tfc_padding", validators=[Optional(), Regexp(r'^\d+$')])
    replay_window = StringField('replay_window (default 32)', name="replay_window", validators=[Optional(), Regexp(r'^\d+$')])
    hw_offload = SelectField(label='hw_offload', name='hw_offload', choices=["no", "yes"])
    copy_df = SelectField(label='copy_df', name='copy_df', choices=["yes", "no"])
    copy_ecn = SelectField(label='copy_ecn', name='copy_ecn', choices=["yes", "no"])
    copy_dscp = SelectField(label='copy_dscp', name='copy_dscp', choices=["out", "in", "yes", "no"])
    start_action = SelectField(label='start_action', name='start_action', choices=["none", "trap", "start"])
    close_action = SelectField(label='close_action', name='close_action', choices=["none", "trap", "start"])

    # Secret/auth

