from bson import SON, ObjectId
from mongoengine import StringField, DateTimeField, IntField, DictField, ListField, \
    EmbeddedDocumentField, EmbeddedDocument, BinaryField, EmbeddedDocumentListField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument, BaseScanningResults, \
    BaseScanningRequests


class DNSBL(BaseScannerDocument):
    dns_resolver_ip = StringField()


class PTRConfig(DNSBL):

    dynamic_hints = ListField()
    static_hints = ListField()


class SinkDB_DB(DNSBL):
    api_key = StringField(required=True)
    name_server_name = StringField(required=True)



class SpamHausDB(DNSBL):
    record_mapping = DictField(required=True)
    name_server_name = StringField(required=True)



class SpamHausRequest(BaseScanningRequests):
    error_reason = StringField()
    results = ListField(default=None)
    unknown_mapping = ListField(default=None)

    def add_unknown_mapping(self, ip):
        if self.unknown_mapping:
            self.unknown_mapping.append(ip)
        else:
            self.unknown_mapping = [ip]


    def add_mapping(self, mapping):
        if self.results:
            self.results.append(mapping)
        else:
            self.results = [mapping]

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        pass

    def _get_complete_sub_doc_results(self, I: dict):
        return I


class SinkDBResult(EmbeddedDocument):
    type = StringField()
    classification = StringField()
    operator = StringField()
    date_added = DateTimeField()
    expose_org = IntField()


class SinkDBRequest(BaseScanningRequests):
    meta = {'collection': 'sink_db_results',
            'indexes': [{'fields': ['hash_answer_string']}]}

    results = EmbeddedDocumentField(SinkDBResult)
    error_reason = StringField()

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        pass

    def _get_complete_sub_doc_results(self, I: dict):
        return I
