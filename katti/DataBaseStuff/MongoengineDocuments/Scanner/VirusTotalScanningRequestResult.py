from bson import SON
from mongoengine import StringField, LazyReferenceField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, BaseScanningResults


class BaseVirusTotal(BaseScanningResults):
    meta = {'allow_inheritance': True, 'collection': 'virustotal_results'}
    hash_answer_string = StringField()


class VirusTotalUniversalURLResult(BaseVirusTotal):
    url_vt_id = StringField(required=True)


class VirusTotalUniversalIPResult(BaseVirusTotal):
    pass


class VirusTotalUniversalFileResult(BaseVirusTotal):
    pass


class VirusTotalUniversalDomainResult(BaseVirusTotal):
    pass

class VirusTotalScanningRequest(BaseScanningRequests):
    meta = {'allow_inheritance': True, 'collection': 'virustotal_requests'}
    api_endpoint = StringField(required=True)
    result = LazyReferenceField(BaseVirusTotal)
    own_api_key = StringField(default=None)

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        if self.result:
            BaseVirusTotal.objects(id=self.result.id).modify(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        if self.result:
            I.update({'result': BaseVirusTotal.objects().as_pymongo().get(id=self.result.id)})

