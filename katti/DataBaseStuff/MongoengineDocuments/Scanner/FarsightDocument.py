from bson import SON
from mongoengine import StringField, ListField, DateTimeField, IntField, BooleanField, \
    URLField, LazyReferenceField, DynamicField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import (BaseScanningRequests,
                                                                                      BaseScanningResults, BaseScannerDocument)


class FarsightDocument(BaseScannerDocument):
    api_key = StringField(required=True)


class FarsightQuerryResult(BaseScanningResults):
    meta = {'collection': 'farsight_records',
            'indexes': [('ooi','type', 'time_first', 'type', 'bailiwick', 'record')]}
    time_first = DateTimeField()
    time_last = DateTimeField()
    count = IntField()
    bailiwick = StringField()
    type = StringField()
    record = DynamicField()

    time_zone = BooleanField(default=False)

    @classmethod
    def ensure_indexes(cls):
        super().ensure_indexes()
        cls._get_collection().create_index('record.$**')


class FarsightRequest(BaseScanningRequests):
    farsight_querry_results = ListField(LazyReferenceField(FarsightQuerryResult))
    result_counter = IntField(default=0, min_value=0)
    url = URLField()

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        if self.farsight_querry_results:
            FarsightQuerryResult.objects(id__in=[x.id for x in self.farsight_querry_results]).update(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        I.update({'farsight_querry_results': list(FarsightQuerryResult.objects(id__in=I['farsight_querry_results']).as_pymongo())})
