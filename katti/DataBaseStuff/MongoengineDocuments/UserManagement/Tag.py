import hashlib
from bson import ObjectId
from mongoengine import StringField, DateTimeField, DynamicEmbeddedDocument, \
    EmbeddedDocument, ObjectIdField, EmbeddedDocumentField, BooleanField
from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractNormalDocument


class Ownership(EmbeddedDocument):
    owner = ObjectIdField(default=ObjectId()) #TODO: Change LazyRef. KattiUser


class Tag(AbstractNormalDocument):
    meta = {'collections': "tags"}
    name = StringField(required=True)
    create = DateTimeField(required=True)
    active = BooleanField(default=True)
    ownership = EmbeddedDocumentField(Ownership, required=True)

    @staticmethod
    def get_tag(name: str, time_lord):
        return Tag.objects(name=name.lower()).modify(set_on_insert__ownership=Ownership(owner=time_lord.id))


class MetaData(DynamicEmbeddedDocument):
    tag = ObjectIdField()

    def __hash__(self):
        return int(hashlib.md5(self.to_json().encode()).hexdigest(), 16)
