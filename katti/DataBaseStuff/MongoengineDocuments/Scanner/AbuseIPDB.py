from bson import SON, ObjectId
from mongoengine import StringField, DateTimeField, ListField, IntField, EmbeddedDocumentField, BooleanField, \
    LazyReferenceField, DynamicField
from katti.DataBaseStuff.MongoengineDocuments.Common.Link import IP
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument, \
    BaseScanningRequests, BaseScanningResults



class AbuseIPDBDB(BaseScannerDocument):
    api_key = StringField(required=True)
    url = StringField(required=True)

    @staticmethod
    def get_backward_propagation_results(result_ids: list[ObjectId]) -> list[dict]:
        return [x.get_complete_result() for x in AbsueIPDBRequest.objects(id__in=result_ids)]



class AbuseIPDBReport(BaseScanningResults):
    meta = {'collection': 'abuse_ipdb_reports',
            'indexes': [('hash_str')]}
    hash_str = StringField()
    reportedAt = DateTimeField()
    comment = StringField()
    categories = ListField()
    reporterId = IntField()
    reporterCountryCode = StringField()
    reporterCountryName = StringField()


class AbsueIPDBRequest(BaseScanningRequests):
    meta = {'collection': 'abuse_ipdb_requests'}
    ip_addr = EmbeddedDocumentField(IP)
    isPublic = BooleanField()
    isWhitelisted = BooleanField()
    abuseConfidenceScore = IntField()
    countryCode = StringField()
    countryName = StringField()
    usageType = StringField()
    isp = StringField()
    domain = StringField()
    hostnames = ListField()
    totalReports = IntField()
    numDistinctUsers = IntField()
    lastReportedAt = DateTimeField()
    reports = ListField(LazyReferenceField(AbuseIPDBReport))

    errors = DynamicField()

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        AbuseIPDBReport.objects(id__in=[x.id for x in self.reports]).update(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        I.update({'reports': list(AbuseIPDBReport.objects(id__in=[x.id for x in self.reports]).as_pymongo())})


