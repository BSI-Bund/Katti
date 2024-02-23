import copy
import datetime
import hashlib
import json
from mongoengine import StringField, ListField, EmbeddedDocument, IntField, \
    LazyReferenceField, DateTimeField, EmbeddedDocumentListField, \
    DynamicEmbeddedDocument, DynamicField, ObjectIdField, BooleanField
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument,\
    BaseScanningRequests, BaseScanningResults
from katti.Scanner.DNS.rdata_parser_functions import *


class Evaluation(DynamicEmbeddedDocument):
    type = StringField(required=True)
    settings = ListField(required=True)


class DNSConfig(BaseScannerDocument):

    name_server_ips = ListField(default=['8.8.8.8'], required=True)

    allowed_record_types = ListField(required=True)
    evaluation = EmbeddedDocumentListField(Evaluation)

    any_backup_records = ListField(default=[])


class DNSRecord(BaseScanningResults):
    meta = {'collection': 'dns_records',
            'indexes': [{'fields': ['hash_answer_string']}]}
    hash_answer_string = StringField()
    dns_ttl = IntField()
    record_type = StringField()

#    a_geo_data = EmbeddedDocumentListField()


class DNSRequest(BaseScanningRequests):
    meta = {'collection': 'dns_request'}

    class DNSQuery(EmbeddedDocument):
        additional_num = IntField()
        answer_num = IntField()
        authority_num = IntField()
        flags = ListField()
        opcode = StringField()
        opt_pseudosection = DynamicField()
        axfr = ListField()

        dig_dns_id = IntField()
        query_num = IntField(default=0, min_value=0)
        query_time_ms = IntField(min_value=0)
        dig_when_time = DateTimeField()
        evaluation = ListField(default=None)
        nameserver_ip = StringField()
        status = StringField()

        records = ListField(LazyReferenceField(DNSRecord), default=None)
        authority_records = ListField(LazyReferenceField(DNSRecord), default=None)

        def build_response(self, answer_json, scanner, evaluation_settings: list[Evaluation], ooi, katti_meta_data: SON | None =None):
            self.answer_num = answer_json.get('answer_num', 0)
            self.additional_num = answer_json.get('additional_num', 0)
            self.authority_num = answer_json.get('authority_num', -1)
            self.flags = answer_json.get('flags', [])
            self.opcode = answer_json.get('opcode')
            self.opt_pseudosection = answer_json.get('opt_pseudosection', [])
            self.axfr = answer_json.get('axfr', [])

            self.dig_dns_id = answer_json.get('id', 0)
            self.query_time_ms = answer_json.get('query_time', 0)
            self.query_num = answer_json.get('query_num', 0)
            self.dig_when_time = datetime.datetime.strptime(answer_json.get('when'), '%a %b %d %H:%M:%S %Z %Y') if 'when' in answer_json else None
            del answer_json['question']

            records = self._parse_records(answer_json.get('answer', []), ooi=ooi, scanner=scanner,
                                    katti_meta_data=katti_meta_data, only_id=False)

            if 'authority' in answer_json:
                x = self._parse_records(answer_json.get('authority', []), ooi=ooi, scanner=scanner, katti_meta_data=katti_meta_data)
                self.authority_records = x
            self.records = records
            self.status = answer_json['status']
            if len(evaluation_settings) > 0:
                evaluation(dns_query=self, evaluations=evaluation_settings, records=records)

            return self

        def _parse_records(self, record_data, ooi, scanner, katti_meta_data, only_id: bool = True):
            rdata_parser = RDataParser()
            records = []
            for next_answer in record_data:
                # dns_response = DNSResult(**answer_json)
                rr_type = next_answer['type']
                next_answer['name'] = next_answer['name'].rstrip('.')
                parsed_record = rdata_parser.do_it(record_type=rr_type, rdata=next_answer['data'])
                parsed_record.update({'dns_ttl': next_answer['ttl'], 'record_type': rr_type, 'ooi': ooi})
                help = copy.deepcopy(parsed_record)
                if 'ip_number' in help:
                    del help['ip_number']
                new_record = DNSRecord.get_result_from_db(scanner_obj=scanner,
                                                          ooi=ooi,
                                                          filter={'hash_answer_string': hashlib.md5(
                                                              json.dumps(help).encode()).hexdigest()},
                                                          with_scanner_id=False,
                                                          katti_meta_data=katti_meta_data,
                                                          set_on_insert_dict=parsed_record,
                                                          only_id=only_id)
                records.append(new_record)
            return records

    dig_dns_type = StringField()
    dig_flags = ListField(default=None)
    queries = EmbeddedDocumentListField(DNSQuery, default=[])
    query_counter = IntField(default=0, min_value=0)
    any_failed_request = ObjectIdField()
    prt = BooleanField(default=None)
    ptr_hint = StringField(default=None)

    def _update_sub_documents(self, new_meta_data_as_son: SON):
        if len(self.queries) > 0:
            if self.queries[-1].records:
                DNSRecord.objects(id__in=self.queries[-1].records).update(__raw__={'$addToSet': {'katti_meta_data': new_meta_data_as_son}})
            if self.queries[-1].authority_records:
                DNSRecord.objects(id__in=self.queries[-1].authority_records).update(__raw__={'$addToSet': {'katti_meta_data': new_meta_data_as_son}})

    def _get_complete_sub_doc_results(self, I: dict):
        if len(self.queries) > 0:
            if self.queries[-1].records:
                I['queries'][-1]['records'] = list(DNSRecord.objects(id__in=[record.id for record in self.queries[-1].records]).as_pymongo())
            if self.queries[-1].authority_records:
                I['queries'][-1]['authority_records'] = list(DNSRecord.objects(id__in=[record.id for record in self.queries[-1].authority_records]).as_pymongo())


def evaluation(dns_query: DNSRequest.DNSQuery, evaluations: list[Evaluation], records: list[DNSRecord]):
    record_evalution = {'quad9': False,
                        'A': [],
                        'AAAA': [],
                        'ptr_stuff': None}
    dns_query.evaluation = []
    for evaluation in evaluations:
        match evaluation.type:
            case 'quad9':
                record_evalution['quad9'] = True
            case 'a_record':
                record_evalution['A'].append(evaluation)
            case 'aaaa_record':
                record_evalution['AAAA'].append(evaluation)
            case 'ptr_stuff':
                record_evalution['ptr_stuff'] = evaluation
    if record_evalution['quad9']:
        quad9_auth_check(dns_query)
    for record in records:
        match record.record_type:
            case 'A' | 'AAAA':
                for evaluation in record_evalution.get(record.record_type, []):
                    check_for_match(settings=evaluation.settings, record_type=record.record_type, dns_query=dns_query,
                                    ooi=record.ip_str)
            case 'PTR' if record_evalution['ptr_stuff']:
                check_ptr_stuff(settings=record_evalution['ptr_stuff'], dns_query=dns_query, record=record)

def quad9_auth_check(dns_query: DNSRequest.DNSQuery):
    if dns_query.status == 'NXDOMAIN':
        if dns_query.authority_num == 0:
            dns_query.evaluation.append({'match': True})
            return
    dns_query.evaluation.append({'match': False})


def check_for_match(ooi, settings, dns_query: DNSRequest.DNSQuery, record_type):
    for setting in settings:
        if ooi == setting[0]:
            dns_query.evaluation.append(
                {'record_type': record_type, 'match': True, 'reason': setting[1]})
            return
    dns_query.evaluation.append({'record_type': record_type, 'match': False})


def check_ptr_stuff(settings, dns_query: DNSRequest.DNSQuery, record):
    target = record.target
    for hint in settings.settings:
        if any(x in target for x in hint.get('hints', [])):
            dns_query.evaluation.append(
                {'record_type': 'PTR', 'match': hint.get('hint_type', 'not specified')})
            return
    dns_query.evaluation.append(
        {'record_type': 'PTR', 'match': 'undetermined'})
