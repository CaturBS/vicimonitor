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
    local_id = StringField('ID', name="local_id",
                            validators=[Optional()])

    remote_round = StringField('round', name="remote_round",
                        validators=[Optional(), Regexp(r'^\d+$', message="should be number")])
    remote_auth = SelectField(label='auth', name='remote_auth', choices=["psk"])
    remote_id = StringField('ID', name="remote_id",
                            validators=[Optional()])
    esp_proposals = StringField('esp_proposals', name="esp_proposals")

    # Check needed
    authby = SelectField(label='Auth By', name='authby', choices=["secret"])
    auto = SelectField(label='auto', name='auto', choices=["ignore", "add", "route", "start"])

    closeaction = SelectField(label='Close Action', name='closeaction', choices=["none", "clear", "hold", "restart"])
    compress = SelectField(label='compress', name='compress', choices=["no", "yes"])
    dpdaction = SelectField(label='dpdaction', name='dpdaction', choices=["none", "clear", "hold", "restart"])
    dpddelay = StringField('dpddelay', name="dpddelay")
    dpdtimeout = StringField('dpdtimeout', name="dpdtimeout")
    inactivity = StringField('inactivity', name="inactivity")
    forceencaps = SelectField(label='forceencaps', name='forceencaps', choices=["no", "yes"])

    ike_encryption = SelectField('IKE Encryption', name='ike_encryption', choices=get_encryption_list())
    ike_integrity = SelectField('IKE Integrity', name='ike_integrity', choices=get_integrity_list())
    ike_dh_group = SelectField('IKE DH Group', name='ike_dh_group', choices=get_dh_group_list())

    ikelifetime = StringField('ikelifetime', name="ikelifetime")
    installpolicy = SelectField(label='installpolicy', name='installpolicy', choices=["yes", "no"])
    keyexchange = SelectField(label='keyexchange', name='keyexchange', choices=["ikev1"])

    lifetime = StringField('lifetime', name="lifetime")

    marginbytes = StringField('marginbytes', name="marginbytes")
    marginpackets = StringField('marginpackets', name="marginpackets")

    margintime = StringField('margintime', name="margintime")

    mark = StringField('mark', name="mark")
    mark_in = StringField('mark_in', name="mark_in")
    mark_out = StringField('mark_out', name="mark_out")

    modeconfig = SelectField(label='modeconfig', name='modeconfig', choices=["pull", "push"])
    reauth = SelectField(label='reauth', name='reauth', choices=["yes", "no"])
    rekey = SelectField(label='rekey', name='rekey', choices=["yes", "no"])
    rekeyfuzz = StringField('rekeyfuzz', name="rekeyfuzz")
    replay_window = StringField('replay_window', name="replay_window")
    reqid = StringField('reqid', name="reqid")
    sha256_96 = SelectField(label='sha256_96', name='sha256_96', choices=["no", "yes"])
    tfc = StringField('tfc', name="tfc")
    type = SelectField(label='sha256_96', name='sha256_96',
                       choices=["tunnel", "transport", "transport_proxy", "passthrough", "drop"])

    left = StringField('left', name="left")
    right = StringField('right', name="right")

    leftallowany = SelectField(label='leftallowany', name='leftallowany', choices=["no", "yes"])
    rightallowany = SelectField(label='rightallowany', name='rightallowany', choices=["no", "yes"])
    leftfirewall = SelectField(label='leftfirewall', name='leftfirewall', choices=["no", "yes"])
    rightfirewall = SelectField(label='rightfirewall', name='rightfirewall', choices=["no", "yes"])
    leftgroups = SelectField(label='leftgroups', name='leftgroups', choices=["no", "yes"])
    rightgroups = SelectField(label='rightgroups', name='rightgroups', choices=["no", "yes"])
    lefthostaccess = SelectField(label='lefthostaccess', name='lefthostaccess', choices=["no", "yes"])
    righthostaccess = SelectField(label='righthostaccess', name='righthostaccess', choices=["no", "yes"])
    leftsourceip = StringField('leftsourceip', name="leftsourceip")
    rightsourceip = StringField('rightsourceip', name="rightsourceip")
    leftsubnet = StringField('leftsubnet', name="leftsubnet")
    rightsubnet = StringField('rightsubnet', name="rightsubnet")
    leftupdown = StringField('leftupdown', name="leftupdown")
    rightupdown = StringField('rightupdown', name="rightupdown")
