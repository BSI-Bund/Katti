from katti.DataBaseStuff.MongoengineDocuments.BaseDocuments import AbstractDynamicalDocument
from mongoengine import StringField, DateTimeField


class Stuff(AbstractDynamicalDocument):
    meta = {'allow_inheritance': True}


class SocialMediaDomain(Stuff):
    domain = StringField(required=True)
    company = StringField(required=True)
    create = DateTimeField(required=True)
