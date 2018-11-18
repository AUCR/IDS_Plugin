"""AUCR IDS plugin function library."""
# coding=utf-8
import os
import udatetime
import ujson
import subprocess
import shutil
from flask import current_app
from dataparserlib.dictionary import flatten_dictionary
from aucr_app import db, create_app
from aucr_app.plugins.IDS_Plugin.models import IDSRules
from aucr_app.plugins.reports.storage.elastic_search import index_data_to_es


def call_back(ch, method, properties, report_id):
    """IDS Processing call back function."""
    app = create_app()
    db.init_app(app)
    rules_dir = os.environ.get('IDS_RULE_DIR') or "aucr_app/plugins/IDS_Plugin/rules/"
    logs_dir = os.environ.get('IDS_LOGS_DIR') or "aucr_app/plugins/IDS_Plugin/logs/"
    with app.app_context():
        ids_report = IDSRules.query.filter_by(id=report_id.decode('utf-8')).first()
        ids_rules_file = current_app.mongo.db.aucr.find_one({"filename": ids_report.ids_plugin_list_name})
        "suricata -v -k none -c suricata.yml -S signatures.rules -r pcap/test.pcap"
        with open("aucr_app/plugins/IDS_Plugin/rules/" + str(ids_report.ids_plugin_list_name), 'w') as test_signature:
            test_signature.write(ids_rules_file["fileobj"])
        args = ["suricata",
                "-c", os.environ.get('SURICATA_CONFIG'),
                "-k", "none",
                "-S", rules_dir + str(ids_report.ids_plugin_list_name),
                "-r", os.environ.get('FILE_FOLDER'),
                "-l", logs_dir,
                ]
        subprocess.check_call(args)
        with open(str(logs_dir + "eve.json"), 'r') as eve_json:
            raw_data = eve_json.readlines()
            for item in raw_data:
                data = ujson.loads(item)
                flat_data_dictionary = flatten_dictionary(data)
                flat_data_dictionary["report"]["process_time"] = udatetime.utcnow()
                # TODO create and use bulk index to ES for better performance.
                index_data_to_es("ids_suricata", flat_data_dictionary["report"])
        shutil.rmtree(logs_dir)
        # TODO upload result data to object storage.
        os.mkdir(logs_dir)
