from mongoengine import StringField, ListField, DateTimeField, DynamicField, IntField

from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractNormalDocument


class LongTermRetryTask(AbstractNormalDocument):
    parent_task_id = StringField(required=True)
    max_day_retries = IntField(default=1)
    day_retries = IntField(default=0)
    children = ListField()
    create = DateTimeField()
    next_execution = DateTimeField(required=True)
    status = StringField(choices=['pending', 'started'])
    last_changed = DateTimeField()
    task_signature = DynamicField()
