"""AUCR IDS_Plugin plugin."""
# coding=utf-8
import os
from multiprocessing import Process
from aucr_app.plugins.tasks.mq import get_a_task_mq
from aucr_app.plugins.IDS_Plugin.ids_processing import call_back
from aucr_app.plugins.IDS_Plugin.routes import ids_page
from aucr_app.plugins.IDS_Plugin.api.rules import ids_rules_api_page
from aucr_app.plugins.IDS_Plugin import models


def load(app):
    """AUCR IDS plugin flask app blueprint registration."""
    app.register_blueprint(ids_page, url_prefix='/IDS')
    app.register_blueprint(ids_rules_api_page, url_prefix='/IDS_API')
    ids_plugin_processor = os.environ.get('IDS_PROCESSOR')
    tasks = "idsrules"
    rabbitmq_server = os.environ.get('RABBITMQ_SERVER')
    rabbitmq_username = os.environ.get('RABBITMQ_USERNAME')
    rabbitmq_password = os.environ.get('RABBITMQ_PASSWORD')
    if ids_plugin_processor:
        p = Process(target=get_a_task_mq, args=(tasks, call_back, rabbitmq_server, rabbitmq_username,
                                                rabbitmq_password))
        p.start()
