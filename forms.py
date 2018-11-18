"""AUCR IDS_Plugin plugin default page forms."""
# coding=utf-8
from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField, SelectMultipleField, IntegerField
from wtforms.validators import Length
from flask_babel import lazy_gettext as _l
from aucr_app.plugins.Horatio.globals import AVAILABLE_CHOICES


class IDSDashboard(FlaskForm):
    """IDS Dashboard flask form."""

    create_new_ids_rule = SubmitField(_l("Create"))


class CreateIDSRule(FlaskForm):
    """IDS Rule Creation Form."""

    ids_rules = TextAreaField(_l('IDS Rules'), validators=[Length(min=0, max=4912000)])
    ids_plugin_list_name = TextAreaField(_l('List Name'), validators=[Length(min=0, max=32)])
    group_access = SelectMultipleField(_l('Group Access'), choices=AVAILABLE_CHOICES)
    submit = SubmitField(_l('Create'))


class EditIDSRules(FlaskForm):
    """Edit IDS list rule."""

    ids_plugin_id = IntegerField(_l('IDS ID'), validators=[Length(min=0, max=12)])
    ids_plugin_list_name = TextAreaField(_l('List Name'), validators=[Length(min=0, max=32)])
    ids_plugin_rules = TextAreaField(_l('IDS Rules'), validators=[Length(min=0, max=4912000)])
    submit = SubmitField(_l('Save'))

    def __init__(self, ids_plugin, *args, **kwargs):
        """Edit IDS_Plugin rule init function."""
        super(EditIDSRules, self).__init__(*args, **kwargs)
        try:
            self.ids_plugin_id = ids_plugin.id
            self.ids_plugin_list_name = ids_plugin.ids_plugin_list_name
        except:
            self.ids_plugin_list_name = ids_plugin["ids_plugin_list_name"]
