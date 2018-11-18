"""AUCR IDS_Plugin plugin route page handler."""
# coding=utf-8
import udatetime
import logging
from aucr_app import db
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from aucr_app.plugins.tasks.mq import get_mq_yaml_configs, index_mq_aucr_report
from aucr_app.plugins.auth.models import Groups, Group, User
from aucr_app.plugins.IDS_Plugin.forms import EditIDSRules, CreateIDSRule, IDSDashboard
from aucr_app.plugins.IDS_Plugin.models import IDSRuleResults, IDSRules
from sqlalchemy import or_

ids_page = Blueprint('IDS', __name__, template_folder='templates')


# TODO maybe use https://pypi.org/project/suricata-prettifier/
@ids_page.route('/dashboard',  methods=['GET', 'POST'])
@login_required
def ids_plugin_route():
    """Dashboard view for IDS Plugin."""
    form = IDSDashboard(request.form)
    if request.method == 'POST':
        request_form = IDSDashboard(request.form)
        if request_form.create_new_ids_rule:
            return redirect("IDS/create")
    page = request.args.get('page', 1, type=int) or 1
    count = page * 10
    ids_plugin_dict = {}
    total = 0
    while total < 10:
        total += 1
        id_item = count - 10 + total
        item = IDSRules.query.filter_by(id=id_item).first()
        if item:
            group_ids = Group.query.filter_by(username_id=current_user.id).all()
            for groups in group_ids:
                if item.group_access == groups.groups_id:
                    author_name = User.query.filter_by(id=item.created_by).first()
                    total_hits = len(IDSRuleResults.query.filter_by(ids_plugin_list_id=item.id).all())
                    item_dict = {"id": item.id, "ids_plugin_list_name": item.ids_plugin_list_name,
                                 "author": author_name.username, "total_hits": total_hits,
                                 "modify_time_stamp": item.modify_time_stamp}
                    ids_plugin_dict[str(item.id)] = item_dict
    prev_url = '?page=' + str(page - 1)
    next_url = '?page=' + str(page + 1)
    return render_template('ids_dashboard.html', table_dict=ids_plugin_dict, form=form, page=page,
                           prev_url=prev_url, next_url=next_url)


@ids_page.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """Create IDS Rule default view."""
    group_info = Groups.query.all()
    if request.method == 'POST':
        form = CreateIDSRule(request.form)
        if form.validate():
            form.ids_rules = request.form["ids_rules"]
            form.ids_plugin_list_name = request.form["ids_plugin_list_name"]
            data = {"filename": form.ids_plugin_list_name, "fileobj": form.ids_rules}
            current_app.mongo.db.aucr.insert_one(data)
            new_ids_rule_list = IDSRules(created_by=current_user.id, group_access=form.group_access.data[0],
                                         ids_plugin_list_name=form.ids_plugin_list_name,
                                         created_time_stamp=udatetime.utcnow(),
                                         modify_time_stamp=udatetime.utcnow())
            db.session.add(new_ids_rule_list)
            db.session.commit()
            flash("The IDS rule has been created.")
            return redirect(url_for('IDS.ids_plugin_route'))
    form = CreateIDSRule(request.form)
    return render_template('create.html', title='Create A New IDS Ruleset', form=form, groups=group_info)


@ids_page.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    """Edit IDS_Plugin view."""
    group_info = Groups.query.all()
    submitted_ids_plugin_id = request.args.get("id")
    group_ids = Group.query.filter_by(username_id=current_user.id).all()
    user_groups = []
    for user_group in group_ids:
        user_groups.append(user_group.groups_id)
    ids_plugin = IDSRules.query.filter_by(id=submitted_ids_plugin_id)
    ids_plugin = ids_plugin.filter(or_(IDSRules.id == submitted_ids_plugin_id,
                                       IDSRules.group_access.in_(user_groups))).first()
    if request.method == 'POST':
        if ids_plugin:
            form = EditIDSRules(request.form)
            if form.validate_on_submit():
                rabbit_mq_server_ip = current_app.config['RABBITMQ_SERVER']
                ids_plugin.ids_rule = request.form["ids_rules"]
                ids_plugin.ids_plugin_list_name = request.form["ids_plugin_list_name"]
                current_app.mongo.db.aucr.delete_one({"filename": ids_plugin.ids_plugin_list_name})
                data = {"filename": request.form["ids_plugin_list_name"], "fileobj": request.form["ids_rules"]}
                current_app.mongo.db.aucr.insert_one(data)
                mq_config_dict = get_mq_yaml_configs()
                files_config_dict = mq_config_dict["reports"]
                for item in files_config_dict:
                    if "ids" in item:
                        logging.info("Adding " + str(ids_plugin.id) + " " + str(item["ids"][0]) + " to MQ")
                        index_mq_aucr_report(str(ids_plugin.id), str(rabbit_mq_server_ip), item["ids"][0])
                flash("The IDS Rule " + str(ids_plugin.ids_plugin_list_name) +
                      " has been updated and the rule is running.")
        return redirect(url_for('IDS.ids_plugin_route'))
    if request.method == "GET":
        if ids_plugin:
            form = EditIDSRules(ids_plugin)
            ids_plugin_list_results = IDSRuleResults.query.filter_by(ids_plugin_list_id=ids_plugin.id)
            ids_plugin_results_dict = {}
            for item in ids_plugin_list_results:
                item_dict = {"id": item.file_matches, "MD5 Hash": item.matches,
                             "Classification": item.file_classification}
                ids_plugin_results_dict[str(item.file_matches)] = item_dict
            ids_plugin_rule_file = current_app.mongo.db.aucr.find_one({"filename": ids_plugin.ids_plugin_list_name})
            ids_plugin_dict = {"id": ids_plugin.id, "ids_rules": ids_plugin_rule_file["fileobj"],
                               "ids_plugin_list_name": ids_plugin.ids_plugin_list_name}
            form.ids_plugin_rules = ids_plugin_rule_file["fileobj"]
            return render_template('edit_ids_rule.html', title='Edit IDS Ruleset', form=form,
                                   groups=group_info, table_dict=ids_plugin_dict,
                                   ids_plugin_results=ids_plugin_results_dict)
        else:
            return ids_plugin_route()
