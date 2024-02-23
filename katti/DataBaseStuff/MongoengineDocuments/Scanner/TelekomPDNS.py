from mongoengine.fields import dateutil, ListField, FloatField, BooleanField, EmbeddedDocumentListField, \
    LazyReferenceField
from katti.DataBaseStuff.MongoengineDocuments.Common.Link import IP
from bson import SON, ObjectId
from mongoengine import EmbeddedDocumentField, IntField, StringField, DateTimeField, EmbeddedDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningResults, \
    BaseScanningRequests, BaseScannerDocument


class TelekomPDNSScannerConfig(BaseScannerDocument):
    url = StringField(required=True)
    user = StringField(required=True)
    api_key = StringField(required=True)

    @staticmethod
    def get_backward_propagation_results(result_ids: list[ObjectId]):
        from katti.ReportDataFunctions.IPAggregations import telekom_results
        return PDNSRequest.objects.aggregate(telekom_results(match_dict={'_id': {'$in': result_ids}}))


class BasePDNSEntry(BaseScanningResults):
    meta = {'allow_inheritance': True,
            'collection': 'telekom_pdns_api_results'}


class PDNSEntry(BasePDNSEntry):

    ip = EmbeddedDocumentField(IP)
    data = StringField()
    count = IntField()
    domain = StringField()
    first_seen = DateTimeField()
    last_seen = DateTimeField()
    last_ttl = IntField()
    max_ttl = IntField()
    min_ttl = IntField()
    type = StringField()

    @classmethod
    def build(cls, result_json):
        new_entry = cls(type=result_json.pop('#type'),
                        avg_ttl= result_json.pop('avg_ttl'),
                        count=result_json.pop('count'),
                        first_seen=dateutil.parser.parse(result_json.pop('first_seen')),
                        last_seen=dateutil.parser.parse(result_json.pop('last_seen')),
                        last_ttl=result_json.pop('last_ttl'),
                        max_ttl=result_json.pop('max_ttl'),
                        min_ttl=result_json.pop('min_ttl')
                        )

        match new_entry.type:
            case 'IPv4':
                new_entry.ip = IP.build_from_ip_str(result_json.pop('data'))
            case _:
                new_entry.data(result_json.pop('data'))
        return new_entry


class AllSubDomains(BasePDNSEntry):
    subdomains = ListField()


class DGAClassifier(BasePDNSEntry):
    class MalwareGuesses(EmbeddedDocument):
        DGA_Guess = StringField()
        DGA_Guess_probabilities = FloatField()

    DGA_360NL = StringField()
    DGA_Classifier = StringField()
    DGA_Guess = StringField()
    DGA_Guess_Probability = FloatField()
    DGA_Probability = FloatField()
    DGArchive = StringField()
    ta505 = BooleanField()
    Malware_Guesses = EmbeddedDocumentListField(MalwareGuesses)


class G2Score(BasePDNSEntry):
    class Classifications(EmbeddedDocument):
        detected_word = StringField()
        dga_classifier = StringField()
        dga_classifier_prob = FloatField()
        dgarchive = StringField()
        domain = StringField()

    DGA_Families = ListField()
    DGA_Family_Count = IntField()
    DGA_Ratio = FloatField()
    DGArchive_Ratio = FloatField()
    Time_Cassandra = FloatField()
    Time_DGA_Classifier = FloatField()
    Time_DGArchive = FloatField()
    Total_Domain_Count = IntField()
    classifications = EmbeddedDocumentListField(Classifications)


class PDNSRequest(BaseScanningRequests):
    meta = {'allow_inheritance': True,
            'collection': 'telekom_pdns_api_requests'}

    endpoint = StringField(required=True)
    results = ListField(LazyReferenceField(BasePDNSEntry))
    counter = IntField(min_value=0, default=0)

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        BasePDNSEntry.objects(id__in=[x.id for x in self.results]).update(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        I.update({'results': list(BasePDNSEntry.objects(id__in=I['results']).as_pymongo())})
