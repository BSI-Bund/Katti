import datetime
from mongoengine import DateTimeField, BooleanField, IntField, ObjectIdField
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import BaseStatistics


class BaseTaskStatistics(BaseStatistics):
    meta = {'collection': 'service_statistics',
            'allow_inheritance': True}

    start_time = DateTimeField(default=datetime.datetime.utcnow(), required=True)
    stop_time = DateTimeField(required=True)

    run_time = IntField(default=0)
    error = BooleanField(default=False)
    service_id = ObjectIdField()
    ttl = DateTimeField(default=datetime.datetime.utcnow())

    @classmethod
    def get_task_with_times(cls, service_id):
        return cls(service_id=service_id,
                   ttl=datetime.datetime.utcnow(),
                   start_time=datetime.datetime.utcnow())


