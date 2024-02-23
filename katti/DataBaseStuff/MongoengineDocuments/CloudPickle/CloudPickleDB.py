import datetime
from mongoengine import BinaryField, StringField, FileField, DateTimeField, IntField, ListField, LazyReferenceField
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractDynamicalDocument


class CloudPickle(AbstractDynamicalDocument):
    meta = {'collection': 'cloud_pickle', 'allow_inheritance': True}
    description = StringField(required=True)
    name = StringField(required=True)
    last_changed = DateTimeField(default=datetime.datetime.utcnow())
    version = IntField(min_value=1, default=1)
    function = BinaryField(required=True)


class APIReportParser(CloudPickle):
    report_type = StringField(required=True, choices=['ip', 'domain', 'url'])
    media_type = StringField(default='"application/json"', required=True)


class CrawlingWorkflowDB(CloudPickle):
    pass


class CrawlingURLGeneratorDB(CloudPickle):
    pass


class CloudCodeAfterRunStuff(CloudPickle):
    pass


class CloudCodeLongRunningRequestWorkflow(CloudPickle):
    pass


class BundleDataParser(CloudPickle):
    media_type = StringField(default='"application/json"', required=True)


class CrawlingRequestDataParser(CloudPickle):
    media_type = StringField(default='"application/json"', required=True)


class CrawlingRequestSummarizerDB(CloudPickle):
    depends_on_parser = ListField(LazyReferenceField( CrawlingRequestDataParser))
    media_type = StringField(default='"application/json"', required=True)


class CeleryWorkflowFunction(CloudPickle):
    pass


class FeedTriggerFunction(CloudPickle):
    pass

