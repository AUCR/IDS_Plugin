"""IDS plugin api functionality."""
# coding=utf-8
import udatetime
from flask import jsonify, g, request, current_app
from aucr_app import db
from aucr_app.plugins.IDS_Plugin.models import IDSRules, IDSRuleResults
from aucr_app.plugins.api.auth import token_auth
from aucr_app.plugins.api.routes import api_page as ids_rules_api_page
from aucr_app.plugins.auth.models import Group
from aucr_app.plugins.errors.api.errors import bad_request


@ids_rules_api_page.route('/ids_rule_list/<int:_id>', methods=['GET'])
@token_auth.login_required
def ids_rule_list(_id):
    """Return IDS_Plugin list API call."""
    if request.method == "GET":
        ids_plugin_rule_list_id = IDSRules.query.filter_by(id=_id).first()
        api_current_user = g.current_user
        group_access_value = Group.query.filter_by(username_id=api_current_user.id,
                                                   groups_id=ids_plugin_rule_list_id.group_access).first()
        if group_access_value:
            return jsonify(IDSRuleResults.query.get_or_404(ids_plugin_rule_list_id.id).to_dict())
        else:
            error_data = {"error": "Not authorized to view this file.", "error_code": 403}
            return jsonify(error_data)


@ids_rules_api_page.route('/ids_rule_list/<int:_id>', methods=['POST'])
@token_auth.login_required
def update_ids_rule_list(_id):
    """API Update Yara Rule."""
    if request.method == "POST":
        ids_plugin_rule = IDSRules.query.filter_by(id=_id).first()
        data = request.form
        if 'ids_plugin_list_name' in data and data['ids_plugin_list_name'] != ids_plugin_rule.ids_plugin_list_name and \
                IDSRules.query.filter_by(ids_plugin_list_name=data['ids_plugin_list_name']).first():
            return bad_request('Please use a different IDS_Plugin rule list name.')
        current_app.mongo.db.aucr.delete_one({"filename": ids_plugin_rule.ids_plugin_list_name})
        data = {"filename": data["ids_plugin_list_name"], "fileobj": data["ids_rules"]}
        current_app.mongo.db.aucr.insert_one(data)
        ids_plugin_rule.from_dict(data)
        db.session.commit()
        return jsonify(ids_plugin_rule.to_dict())


@ids_rules_api_page.route('/ids_rule_results/<int:_id>', methods=['GET'])
@token_auth.login_required
def ids_rule_results(_id):
    """Return IDS_Plugin list results."""
    if request.method == "GET":
        ids_rule_list_id = IDSRules.query.filter_by(id=_id).first()
        api_current_user = g.current_user
        group_access_value = Group.query.filter_by(username_id=api_current_user.id,
                                                   groups_id=ids_rule_list_id.group_access).first()
        if group_access_value:
            ids_list_results = IDSRuleResults.query.filter_by(ids_plugin_list_id=ids_rule_list_id.id).all()
            ids_results_dict = {}
            for item in ids_list_results:
                item_dict = {"id": item.file_matches, "MD5 Hash": item.matches,
                             "Classification": item.file_classification}
                ids_results_dict[str(item.file_matches)] = item_dict
            return jsonify(ids_results_dict)
        else:
            error_data = {"error": "Not authorized to view this file.", "error_code": 403}
            return jsonify(error_data)


@ids_rules_api_page.route('/ids_rule_create/', methods=['POST'])
@token_auth.login_required
def create_ids_rule_list():
    """API Update IDS Rule."""
    if request.method == "POST":
        data = request.form
        if 'ids_plugin_list_name' in data and data['ids_plugin_list_name'] != data.ids_plugin_list_name and \
                IDSRules.query.filter_by(ids_plugin_list_name=data['ids_plugin_list_name']).first():
            return bad_request('Please use a different IDS_Plugin rule list name.')
        data_mongo = {"filename": data["ids_plugin_list_name"], "fileobj": data["ids_rules"]}
        current_app.mongo.db.aucr.insert_one(data_mongo)
        new_ids_rule_list = IDSRules(created_by=int(data["created_by"]), group_access=int(data["group_access"]),
                                     ids_plugin_list_name=str(data["ids_plugin_list_name"]),
                                     created_time_stamp=udatetime.utcnow(), modify_time_stamp=udatetime.utcnow())
        db.session.add(new_ids_rule_list)
        db.session.commit()
        return jsonify(new_ids_rule_list.to_dict())
