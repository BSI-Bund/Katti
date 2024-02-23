import datetime
import json
import sys
import traceback
import typing
from katti.DataBaseStuff.MongoengineDocuments.Common.Link import IP
from mongoengine.fields import dateutil
import requests
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    TelekomPassiveDNSScannerExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.KattiUtils.Exceptions.CommonExtensions import ExtremeFailure
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI
from requests.auth import HTTPBasicAuth
from katti.DataBaseStuff.MongoengineDocuments.Scanner.TelekomPDNS import PDNSEntry, PDNSRequest, TelekomPDNSScannerConfig, \
    AllSubDomains, DGAClassifier, G2Score
from katti.Scanner.QuotaMechanic import DayBlockException


@dataclass(config=PydanticConfig)
class TelekompDNSOOi(OOI):
    #TODO: Ähm ja, hier sollte noch irgendwie ein etwas ausgereifter Check hin...
    pass


@dataclass(config=PydanticConfig)
class TelekomPDNSRequest(BaseScanningRequestForScannerObject):
    endpoint: typing.Literal['domain', 'ip', 'nxdomain', 'dga_classifier', 'ip_for_g2'] = 'domain'

    @staticmethod
    def ooi_cls():
        return TelekompDNSOOi

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [TelekompDNSOOi(raw_ooi=ooi) for ooi in raw_oois]

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'ips' | 'ipv4' | 'ipv6' | 'domain':
                return True
            case _:
                return False



class TelekomPDNS(BaseScanner):
    scanner_document: TelekomPDNSScannerConfig
    scanning_request: TelekomPDNSRequest

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import telekom_api
        return [TelekomPDNSRequest, telekom_api]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        match ooi_type:
            case 'ipv4' | 'ipv6':
                return {f'{scanner_name}_ip': {'endpoint': 'ip'},
                        f'{scanner_name}_g2': {'endpoint': 'ip_for_g2'}}
            case 'domain':
                return {f'{scanner_name}_domain': {'endpoint': 'domain'},
                        f'{scanner_name}_nxdomain': {'endpoint': 'nxdomain'},
                        f'{scanner_name}_dga_classifier': {'endpoint': 'dga_classifier'}}

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return TelekomPassiveDNSScannerExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'telekom_pdns'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return TelekomPDNSScannerConfig(**config)

    @property
    def additional_filter_fields(self) -> dict:
        return {'endpoint': self.scanning_request.endpoint}

    @property
    def kwargs_for_building_scanning_request(self) -> dict:
        return {'endpoint': self.scanning_request.endpoint}

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return PDNSRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return TelekomPDNSScannerConfig

    def _do_your_scanning_job(self):
        match self.scanning_request.endpoint:
            case 'dga_classifier':
                v = 'v2'
            case _:
                v = 'v1'
        try:
            response = requests.get(
                f'{self.scanner_document.url}/{v}/{self.scanning_request.endpoint}/{self.next_ooi_obj.ooi}?format=json',
                auth=HTTPBasicAuth(self.scanner_document.user, self.scanner_document.api_key), )
        except Exception:
            self.logger.exception(f'Telekom PDNS fail: {traceback.format_exception(*sys.exc_info())}')
            raise
        else:
            match response.status_code:
                case 200:
                    resp_json = json.loads(response.content)
                    self._set_and_get_quota(response.headers)
                    match self.scanning_request.endpoint:
                        case 'ip' | 'domain' | 'nxdomain':
                            self._sub_domains = []
                            for key in resp_json:
                                filter, set_on_insert, update = self._parse_response(resp_json[key],
                                                                                     endpoint=self.scanning_request.endpoint)
                                if filter:
                                    x = PDNSEntry.get_result_from_db(scanner_obj=self,
                                                                     filter=filter,
                                                                     update={'$set': update},
                                                                     set_on_insert_dict=set_on_insert,
                                                                     with_scanner_id=False,
                                                                     ooi=self.next_ooi_obj.ooi,
                                                                     only_id=True)
                                    self.scanning_result.results.append(x)
                            if len(self._sub_domains):
                                self.scanning_result.results.append(AllSubDomains.get_result_from_db(scanner_obj=self,
                                                                                                     update={
                                                                                                         '$addToSet': {
                                                                                                             'subdomains': {
                                                                                                                 '$each': self._sub_domains}}},
                                                                                                     ooi=None,
                                                                                                     filter={
                                                                                                         'ooi': self.next_ooi_obj.ooi},
                                                                                                     only_id=True))
                        case 'all_subdomains':
                            self.scanning_result.results.append(AllSubDomains.get_result_from_db(scanner_obj=self,
                                                                                                 filter={
                                                                                                     'ooi': self.next_ooi_obj.ooi},
                                                                                                 update={'$addToSet': {
                                                                                                     'subdomains': {
                                                                                                         '$each': resp_json.get(
                                                                                                             'all_subdomains',
                                                                                                             [])}}},
                                                                                                 ooi=None,
                                                                                                 only_id=True))
                        case 'dga_classifier':
                            malware_guesses = resp_json.pop('Malware_Guesses')
                            malware_guesses = [DGAClassifier.MalwareGuesses(**malware_guesses[x]) for x in
                                               malware_guesses]

                            new_dga_clas = DGAClassifier(Malware_Guesses=malware_guesses,
                                                         ooi=resp_json.pop('Requested_domain'), **resp_json)
                            new_dga_clas.save()
                            self.scanning_result.results.append(new_dga_clas.id)

                        case 'ip_for_g2':
                            classifications = [G2Score.Classifications(**x) for x in resp_json.pop('Classifications')]
                            new_g2_scroe = G2Score(DGA_Families=resp_json.get('DGA_Families'),
                                                   DGA_Family_Count=resp_json.get('DGA_Family_Count'),
                                                   DGA_Ratio=resp_json.get('DGA_Ratio'),
                                                   DGArchive_Ratio=resp_json.get('DGArchive_Ratio'),
                                                   Time_Cassandra=float(resp_json.get('Time_Cassandra')),
                                                   Time_DGA_Classifier=float(resp_json.get('Time_DGA_Classifier')),
                                                   Time_DGArchive=float(resp_json.get('Time_DGArchive')),
                                                   Total_Domain_Count=resp_json.get('Total_Domain_Count'),
                                                   classifications=classifications,
                                                   ooi=self.next_ooi_obj.ooi)
                            new_g2_scroe.save()
                            self.scanning_result.results.append(new_g2_scroe)
                case _:
                    self._check_quota_pdns(response.headers)
                    self.logger.error(f'Bad status code: {response.status_code}')
                    raise ExtremeFailure(f'Bad status code: {response.status_code}')

    def _check_quota_pdns(self, response_headers):
            quota = self._set_and_get_quota(response_headers)
            if quota and quota == 0:
                raise DayBlockException()

    def _set_and_get_quota(self, response_headers):
        try:
            quota = response_headers.get('X-RateLimit-Remaining-Day')
            self.quota.set_remaining_quota(quota)
        except Exception:
            quota = None
        return quota

    def _parse_response(self, resp_json, endpoint):
        filter = {'type': resp_json.pop('#type').lower(), }
        set_on_insert = {'first_seen': dateutil.parser.parse(resp_json.pop('first_seen')) if resp_json.get('first_seen') else None}  # print(set_on_insert)
        match endpoint:
            case 'ip' | 'domain':
                if filter['type'] == 'subdomain':
                    self._sub_domains.append(
                        {'katti_created': datetime.datetime.fromordinal(datetime.date.today().toordinal()),
                         'domain': resp_json.get('domain')})
                    return None, None, None
                update = {
                    'avg_ttl': resp_json.pop('avg_ttl'),
                    'count': resp_json.pop('count'),
                    'last_seen': dateutil.parser.parse(resp_json.pop('last_seen')) if resp_json.get('last_seen') else None,
                    'last_ttl': resp_json.pop('last_ttl'),
                    'max_ttl': resp_json.pop('max_ttl'),
                    'min_ttl': resp_json.pop('min_ttl')
                }
            case 'nxdomain':
                update = {
                    'count': resp_json.pop('count'),
                    'last_seen': dateutil.parser.parse(resp_json.pop('last_seen')) if resp_json[
                                                                                          'last_seen'] in resp_json else None}

        match filter['type']:
            case 'ipv4' | 'ipv6' if not self.scanning_request.endpoint == 'ip':
                ip = IP.build_from_ip_str(resp_json.pop('data'))
                filter.update({'ip.ip_number': ip.ip_number})
                set_on_insert.update({'ip.ip_str': ip.ip_str, 'ip.version': ip.version})
            case _ if 'data' in resp_json:
                filter.update({'data': resp_json.get('data')})
            case _ if 'domain' in resp_json:
                filter.update({'domain': resp_json.get('domain')})
        return filter, set_on_insert, update
