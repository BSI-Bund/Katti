import datetime
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import BaseStatistics
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import Ownership
from mongoengine import DateTimeField, BooleanField, IntField, StringField, EmbeddedDocumentField


class BaseTaskStatistics(BaseStatistics):
    meta = {'collection': 'task_statistics',
            'allow_inheritance': True}

    error = BooleanField(default=False)
    task_timeout = BooleanField(default=False)
    retry_exception = BooleanField(default=False)
    retry_counter = IntField(default=0, min_value=0)

    task_id = StringField(required=True)
    ttl = DateTimeField(default=datetime.datetime.utcnow())
    ownership = EmbeddedDocumentField(Ownership)


    @classmethod
    def get_task_with_times(cls, task_id, **kwargs):
        return cls(task_id=task_id,
                   ttl=datetime.datetime.utcnow(),
                   start_time=datetime.datetime.utcnow(),
                   **kwargs)
