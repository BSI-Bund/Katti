import datetime
from bson import SON
from mongoengine import StringField, ListField, EmbeddedDocument, EmbeddedDocumentListField, IntField, \
    DateTimeField, LazyReferenceField
from katti.DataBaseStuff.MongoengineDocuments.StatisticDocuments.BaseServiceStatistics import BaseStatistics
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import (BaseScannerDocument,
                                                                                      BaseScanningRequests, BaseScanningResults)


class GoogleSafeBrowserConfig(BaseScannerDocument):
    threat_types = ListField(default=["THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                      "POTENTIALLY_HARMFUL_APPLICATION"])
    platform_types = ListField(default=["ANY_PLATFORM"])
    docker_ip = StringField(required=True)
    docker_port = IntField(required=True)
    api_key = StringField(required=True)


class GSBFindings(BaseScanningResults):
    meta = {'collection': 'gsb_results',
            'indexes': [('url', 'findings')]}

    class Findings(EmbeddedDocument):
        platformType = StringField()
        threatType = StringField()

    findings = EmbeddedDocumentListField(Findings, default=[])

    finding_counter = IntField(default=0, min_value=0)
    url = StringField()


class GSBRequest(BaseScanningRequests):
    meta = {'collection': 'gsb_request'}
    finding_counter = IntField(default=0, min_value=0)
    findings = LazyReferenceField(GSBFindings)

    def save_scanning_result(self):
        self.save()
    def build_response(self, answer_json, onwership: SON, meta_data: SON =None):
        new_answer = GSBFindings()
        if 'matches' in answer_json:
            for result in answer_json['matches']:
                new_answer.findings.append(
                    GSBFindings.Findings(platformType=result['platformType'], threatType=result['threatType']))
        update = {'$setOnInsert': {'create': datetime.datetime.utcnow(),
                                   'finding_counter': len(new_answer.findings),
                                   'ownership': onwership},
                  '$set': {'last': datetime.datetime.utcnow()}}
        if meta_data:
            update.update({'$addToset': {'meta_data': meta_data}})
            self.findings = GSBFindings.objects(url=self.ooi, findings=new_answer.findings).modify(__raw__=update, upsert=True,  new=True)
        return self

    def _update_sub_documents(self, new_meta_data_as_SON: SON):
        if self.findings:
            GSBFindings.objects(id=self.findings.id).update(add_to_set__katti_meta_data=new_meta_data_as_SON)

    def _get_complete_sub_doc_results(self, I: dict):
        if self.findings:
            I.update({'findings': GSBFindings.objects.as_pymongo().get(id=self.findings.id)})


class GSbServerStatus(BaseStatistics):
    meta = {'collection': 'gsb_stats'}

    QueriesByDatabase = IntField()
    QueriesByCache = IntField()
    QueriesByAPI = IntField()
    QueriesFail = IntField()
    DatabaseUpdateLag = IntField()
    ttl = DateTimeField()

    error = StringField()
