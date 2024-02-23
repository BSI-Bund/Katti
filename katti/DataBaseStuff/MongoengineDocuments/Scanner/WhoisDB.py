from bson import SON
from mongoengine import DateTimeField, BooleanField, ListField, StringField, LazyReferenceField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScanningResults, BaseScannerDocument


class WhoisDB(BaseScannerDocument):
    pass


class WhoisResult(BaseScanningResults):
    creation_date = DateTimeField()
    expiration_date = DateTimeField()
    last_updated = DateTimeField()
    dnssec = BooleanField()
    emails = ListField()
    name_servers = ListField()
    registrant = StringField()
    registrant_country = StringField()
    registrar = StringField()
    status = StringField()
    statuses = ListField()
    tld = StringField()


class WhoisRequestDB(BaseScanningRequests):
    meta = {'collection': 'whois_request'}
    result = LazyReferenceField(WhoisResult, default=None)
    error = StringField()

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        if self.result:
            WhoisResult.objects(self.result.id).update(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        if self.result:
            I.update({'result': WhoisResult.objects.as_pymongo().get(id=self.result.id)})