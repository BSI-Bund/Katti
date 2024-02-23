from mongoengine import StringField
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import BaseStatistics


class DockerStart(BaseStatistics):
    container_id = StringField(required=True)
