import datetime
from mongoengine import StringField, EmailField, DateTimeField, BooleanField, EmbeddedDocument, IntField, \
    EmbeddedDocumentField, EmbeddedDocumentListField
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractNormalDocument


class API(EmbeddedDocument):
    class Endpoint(EmbeddedDocument):
        endpoint_name = StringField(required=True)
        access = BooleanField(default=False, required=True)
        daily_rate = IntField(min_value=0, required=True, default=10000)
        frontend_minute_rate = IntField(min_value=1, default=100)

    key = StringField(min_length=1, max_length=32, required=True)
    endpoints = EmbeddedDocumentListField(Endpoint)


class TimeLord(AbstractNormalDocument):
    meta = {'collection': 'time_lords'}

    first_name = StringField(min_length=2, max_length=50, required=True)
    last_name = StringField(min_length=2, max_length=50, required=True)
    department = StringField(min_length=2, max_length=50, required=True)
    email = EmailField(required=True, unique=True)

    created = DateTimeField(default=datetime.datetime.utcnow())
    las_update = DateTimeField()

    user_is_active = BooleanField(default=True)
    api = EmbeddedDocumentField(API, required=True)


    @staticmethod
    def get_system_user_id():
        # ich hasse imports in python
        from katti.KattiUtils.Configs.ConfigKeys import SYSTEM_USER
        user = SYSTEM_USER()
        return user.id
