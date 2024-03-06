import os

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField
from wtforms.validators import DataRequired, InputRequired


class ConnectionForm(FlaskForm):

    @staticmethod
    def get_dh_group_list()->list:
        path = os.path.join(os.getcwd(), "ah", "dhgroups.txt")
        lines = []
        with open(path) as file:
            for line in file:
                line = line.strip()
                lines.append(line)
        return lines
    @staticmethod
    def get_integrity_list()->list:
        path = os.path.join(os.getcwd(), "ah", "integrity.txt")
        lines = []
        with open(path) as file:
            for line in file:
                line = line.strip()
                lines.append(line)
        return lines

    @staticmethod
    def get_encryption_list() -> list:
        path = os.path.join(os.getcwd(), "ah", "encryption.txt")
        lines = []
        with open(path) as file:
            for line in file:
                line = line.strip()
                lines.append(line)
        return lines

    name = StringField('connection_name', name="name", validators=[InputRequired()])
    # ah_encryption = SelectField('AH Encryption', name='ah_encryption', choices=get_encryption_list())
    # ah_integrity = SelectField('AH Integrity', name='ah_integrity', choices=get_integrity_list())
    # ah_dh_group = SelectField('AH DH Group', name='ah_dh_group', choices=get_dh_group_list())
    aggressive = SelectField(label='aggressive', name='aggressive',choices=["no", "yes"])
    authby = SelectField(label='Auth By', name='authby',choices=["secret"])
    auto = SelectField(label='auto', name='auto',choices=["ignore", "add", "route", "start"])

    closeaction = SelectField(label='Close Action', name='closeaction',choices=["none", "clear", "hold", "restart"])
    compress = SelectField(label='compress', name='compress',choices=["no", "yes"])
    dpdaction = SelectField(label='dpdaction', name='dpdaction',choices=["none", "clear", "hold", "restart"])
    dpddelay = StringField('dpddelay', name="dpddelay")
    dpdtimeout = StringField('dpdtimeout', name="dpdtimeout")
    inactivity = StringField('inactivity', name="inactivity")
    esp_encryption = SelectField('ESP Encryption', name='esp_encryption', choices=get_encryption_list())
    esp_integrity = SelectField('ESP Integrity', name='esp_integrity', choices=get_integrity_list())
    esp_dh_group = SelectField('ESP DH Group', name='esp_dh_group', choices=get_dh_group_list())
    forceencaps = SelectField(label='forceencaps', name='forceencaps',choices=["no", "yes"])
    fragmentation = SelectField(label='fragmentation', name='fragmentation',choices=["yeas", "accept", "force","no"])

    ike_encryption = SelectField('IKE Encryption', name='ike_encryption', choices=get_encryption_list())
    ike_integrity = SelectField('IKE Integrity', name='ike_integrity', choices=get_integrity_list())
    ike_dh_group = SelectField('IKE DH Group', name='ike_dh_group', choices=get_dh_group_list())

    ikedscp = StringField('ikedscp', name="ikedscp")
    ikelifetime = StringField('ikelifetime', name="ikelifetime")
    installpolicy = SelectField(label='installpolicy', name='installpolicy',choices=["yes", "no"])
    keyexchange = SelectField(label='keyexchange', name='keyexchange',choices=["ikev1"])
    keyingtries = StringField('keyingtries', name="keyingtries")

    lifetime = StringField('lifetime', name="lifetime")

    marginbytes = StringField('marginbytes', name="marginbytes")
    marginpackets = StringField('marginpackets', name="marginpackets")

    margintime = StringField('margintime', name="margintime")

    mark = StringField('mark', name="mark")
    mark_in = StringField('mark_in', name="mark_in")
    mark_out = StringField('mark_out', name="mark_out")

    modeconfig = SelectField(label='modeconfig', name='modeconfig',choices=["pull", "push"])
    reauth = SelectField(label='reauth', name='reauth',choices=["yes", "no"])
    rekey = SelectField(label='rekey', name='rekey',choices=["yes", "no"])
    rekeyfuzz = StringField('rekeyfuzz', name="rekeyfuzz")
    replay_window = StringField('replay_window', name="replay_window")
    reqid = StringField('reqid', name="reqid")
    sha256_96 = SelectField(label='sha256_96', name='sha256_96',choices=["no", "yes"])
    tfc = StringField('tfc', name="tfc")
    type = SelectField(label='sha256_96', name='sha256_96',choices=["tunnel", "transport", "transport_proxy", "passthrough", "drop"])

    left = StringField('left', name="left")
    right = StringField('right', name="right")

    leftallowany = SelectField(label='leftallowany', name='leftallowany',choices=["no", "yes"])
    rightallowany = SelectField(label='rightallowany', name='rightallowany',choices=["no", "yes"])
    leftfirewall = SelectField(label='leftfirewall', name='leftfirewall',choices=["no", "yes"])
    rightfirewall = SelectField(label='rightfirewall', name='rightfirewall',choices=["no", "yes"])
    leftgroups = SelectField(label='leftgroups', name='leftgroups',choices=["no", "yes"])
    rightgroups = SelectField(label='rightgroups', name='rightgroups',choices=["no", "yes"])
    lefthostaccess = SelectField(label='lefthostaccess', name='lefthostaccess',choices=["no", "yes"])
    righthostaccess = SelectField(label='righthostaccess', name='righthostaccess',choices=["no", "yes"])


