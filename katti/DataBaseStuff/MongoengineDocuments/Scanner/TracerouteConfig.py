from bson import SON
from mongoengine import ListField, IntField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument, BaseScanningRequests


class TracerouteConfig(BaseScannerDocument):
    pass


class TracerouteAnswer(BaseScanningRequests):
    meta = {'collection': 'traceroute_requests'}
    hops = ListField()
    hops_counter = IntField(min_value=0, default=0)

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        pass

    def _get_complete_sub_doc_results(self, I: dict):
        pass


