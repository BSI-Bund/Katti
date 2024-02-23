from mongoengine import Document, StringField


class MaxMindConfig(Document):
    country_db_name = StringField()