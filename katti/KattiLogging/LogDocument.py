import datetime
from mongoengine import DateTimeField, IntField, StringField

from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractDynamicalDocument


class BaseLogDocument(AbstractDynamicalDocument):
    meta = {'allow_inheritance': True,
            'collection': 'logs_new',
            'indexes': [{'fields': ['logger_name'],
                         'name': 'name_log'}]}

    logger_name = StringField()
    timestamp = DateTimeField(default=datetime.datetime.utcnow())
    level = StringField()
    thread = IntField()
    thread_name = StringField()
    message = StringField()
    file_name = StringField()
    module = StringField()
    method = StringField()
    line_number = IntField()
    task_id = StringField()
    machine_node = StringField()


class CommonLogDocument(BaseLogDocument):
    pass


class CeleryLog(BaseLogDocument):
    pass


class DockerLog(BaseLogDocument):
    pass


class HeartBeatLogs(BaseLogDocument):
    pass