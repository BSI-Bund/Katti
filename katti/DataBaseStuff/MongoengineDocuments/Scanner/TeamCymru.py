from bson import SON, ObjectId
from katti.DataBaseStuff.MongoengineDocuments.Common.Link import IP
from mongoengine import StringField, IntField, DateTimeField, LazyReferenceField, ListField, BooleanField, \
    EmbeddedDocumentField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument, \
    BaseScanningRequests, BaseScanningResults


class TeamCymruDB(BaseScannerDocument):
    @staticmethod
    def get_backward_propagation_results(result_ids: list[ObjectId]):
        from katti.ReportDataFunctions.IPAggregations import team_cymru_results
        return TeamCymruRequest.objects.aggregate(team_cymru_results(match_dict={'_id': {'$in': result_ids}}))


class TeamCymruResult(BaseScanningResults):
    meta = {'collection': 'team_cymru_results',
            'indexes': [('ip_v4', 'asn_number', 'cidr', 'country_code', 'registry', 'allocated', 'asn_name'),
                        ('ip_v6', 'asn_number', 'cidr', 'country_code', 'registry', 'allocated', 'asn_name')]}
    asn_number = IntField()
    ip_adr = EmbeddedDocumentField(IP)
    cidr = StringField()
    country_code = StringField()
    registry = StringField()
    allocated = DateTimeField()
    as_name = StringField()

    no_matching_asn = BooleanField(default=None)
    error_ip = StringField()


class TeamCymruRequest(BaseScanningRequests):
    meta = {'collection': 'team_cymru_requests'}
    entries = ListField(LazyReferenceField(TeamCymruResult))

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        TeamCymruResult.objects(id__in=[x.id for x in self.entries]).update(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        I.update({'entries': list(TeamCymruResult._get_collection().find({'_id':{'$in': [x.id for x in self.entries]}}))})




