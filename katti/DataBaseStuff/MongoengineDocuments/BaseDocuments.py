import datetime
from mongoengine import Document, DynamicDocument, StringField, DateTimeField, FloatField


class AbstractNormalDocument(Document):
    meta = {'abstract': True,
            'db_alias': 'Katti',
            'auto_create_index': False}


class AbstractDynamicalDocument(DynamicDocument):
    meta = {'abstract': True,
            'db_alias': 'Katti',
            'auto_create_index': False}


class BaseConfig(AbstractDynamicalDocument):
    meta = {'collection': 'configurations',
            'allow_inheritance': True}

    name = StringField(required=True, unique=True)

    @staticmethod
    def collection_name() -> str:
        return 'configurations'


class BaseStatistics(AbstractDynamicalDocument):
    meta = {'abstract': True,
            'db_alias': 'Katti'}

    start_time = DateTimeField(default=datetime.datetime.utcnow(), required=True)
    stop_time = DateTimeField(required=True)

    run_time = FloatField()
    def stop_and_save(self):
        self.stop_time = datetime.datetime.utcnow()
        self.run_time = (self.stop_time - self.start_time).total_seconds()
        self.save()
