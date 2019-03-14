# coding=utf-8
"""IDS Plugin default database tables."""
import udatetime as datetime
from aucr_app import db


class IDSRuleResults(db.Model):
    """IDS Result database table."""

    __tablename__ = 'ids_rule_results'
    id = db.Column(db.Integer, primary_key=True)
    ids_plugin_list_id = db.Column(db.Integer, db.ForeignKey('ids_rules.id'))
    matches = db.Column(db.String(3072))
    pcap_matches = db.Column(db.Integer, db.ForeignKey('uploaded_file_table.id'))
    pcap_classification = db.Column(db.String(3072))
    run_time = db.Column(db.DateTime)

    def __repr__(self):
        return '<IDS Rule Results {}>'.format(self.ids_plugin_list_id)

    def to_dict(self):
        """Return dictionary object type for API calls."""
        data = {
            'id': self.id,
            'ids_plugin_list_id': self.ids_plugin_list_id,
            'matches': self.matches,
            'run_time': self.run_time.isoformat() + 'Z',
            'file_matches': self.pcap_matches,
            'file_classification': self.pcap_classification,
        }
        return data


class IDSRules(db.Model):
    """IDS Plugin data default table for aucr."""

    __searchable__ = ['id', 'ids_plugin_list_name', 'modify_time_stamp', 'created_by']
    __tablename__ = 'ids_rules'
    id = db.Column(db.Integer, primary_key=True)
    ids_plugin_list_name = db.Column(db.String(32), index=True, unique=True)
    created_time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    modify_time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_access = db.Column(db.Integer, db.ForeignKey('groups.id'))
    ids_rules = db.Column(db.String(4912000), index=True)

    def __repr__(self):
        return '<IDS {}>'.format(self.ids_plugin_list_name)

    def to_dict(self):
        """Return dictionary object type for API calls."""
        data = {
            'id': self.id,
            'ids_plugin_list_name': self.ids_plugin_list_name,
            'last_seen': self.created_time_stamp.isoformat() + 'Z',
            'modify_time_stamp': self.modify_time_stamp.isoformat() + 'Z',
            'created_by': self.created_by,
            'group_access': self.group_access,
            'ids_rule': self.ids_rules
        }
        return data

    def from_dict(self, data):
        """Process from dictionary object type for API IDS Rule Post."""
        for field in ['ids_plugin_list_name', 'group_access', 'created_by']:
            if field in data:
                setattr(self, field, data[field])
