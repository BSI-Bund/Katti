from mongoengine import StringField, URLField, DateTimeField, FileField, EmbeddedDocument, \
    EmbeddedDocumentListField
from katti.DataBaseStuff.MongoengineDocuments.Feeds.BaseFeedDocuments import BaseFeedDB, BaseFeedEntry


class MaxMindDB(BaseFeedDB):
    class DB(EmbeddedDocument):
        url = URLField(required=True)
        db_type = StringField(required=True)

    dbs = EmbeddedDocumentListField(DB, required=True)
    license_key = StringField(required=True)


class MaxMindDBFile(BaseFeedEntry):
    meta = {'collection': 'maxmind_db_files'}

    def _build_update_dict_for_update_one(self) -> dict:
        return {}

    def _build_filter_dict_for_update_one(self) -> dict:
        return {}

    day = DateTimeField()
    db_type = StringField(choices=['Country', 'ASN', 'City'], required=True)
    db_file = FileField(required=True, db_alias='Katti')