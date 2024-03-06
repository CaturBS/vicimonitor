import os

from flask_wtf import FlaskForm
from wtforms import SelectField, HiddenField
from wtforms.validators import DataRequired, InputRequired


class ChooseEncryptionForm(FlaskForm):

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

    encryption = SelectField('Encryption', name='encryption', choices=get_encryption_list())
    integrity = SelectField('Integrity', name='integrity', choices=get_integrity_list())
    dh_group = SelectField('DH Group', name='dh_group', choices=get_dh_group_list())

    def __init__(self, idx: str, **kwargs):
        super().__init__(**kwargs)
        self.idx = idx
