import json
import sys
import traceback
import typing
from random import randint
import requests
from pydantic import AnyUrl
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    GSBExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI, RetryException
from katti.DataBaseStuff.MongoengineDocuments.Scanner.GoogleSafeBrwosingConfig import GSBRequest, GoogleSafeBrowserConfig, \
    GSBFindings


@dataclass(config=PydanticConfig)
class URLForGSB(OOI):
    raw_ooi: AnyUrl = 'http://example.com'


@dataclass(config=PydanticConfig)
class URLsForGSBRequest(BaseScanningRequestForScannerObject):

    @staticmethod
    def ooi_cls():
        return URLForGSB

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [URLForGSB(raw_ooi=url) for url in raw_oois]

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'url':
                return True
            case _:
                return False



class GoogleSafeBrowsing(BaseScanner):
    scanner_document: GoogleSafeBrowserConfig

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import gsb_scanning_task
        return [URLsForGSBRequest, gsb_scanning_task]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return GSBExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'gsb'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return GoogleSafeBrowserConfig(**config)

    def _build_threat_info(self, url):
        ti = {}
        ti.update({'threatInfo': {'threatTypes': self.scanner_document.threat_types,
                                  'platformTypes': self.scanner_document.platform_types,
                                  'threatEntryTypes': ['URL'],
                                  'threatEntries': [{'url': url}]}})
        return ti

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return GSBRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return GoogleSafeBrowserConfig

    def _do_your_scanning_job(self):
        headers = {'content-type': 'application/json'}
        try:
            response = requests.post(
                url=f'http://{self.scanner_document.docker_ip}:{self.scanner_document.docker_port}/v4/threatMatches:find',
                data=json.dumps(self._build_threat_info(self.next_ooi_obj.ooi)),
                headers=headers,
                timeout=10)
        except requests.exceptions.ConnectionError:
            self.logger.error(f'ConnectionError, server down?')
            self.retry_args.update({'countdown': randint(30*60, 60*60)})
            raise RetryException()
        else:
            self._produce_response(response.content)

    def _produce_response(self, response_content):
        self.logger.debug('Produce response')
        try:
            content = json.loads(response_content.decode('utf-8'))
        except Exception:
            self.logger.error(f'{self.next_ooi_obj.ooi}\n {traceback.format_exception(*sys.exc_info())}')
            self._scanning_result = None
        else:
            findings = []
            if 'matches' in content:
                for result in content['matches']:
                    findings.append(GSBFindings.Findings(platformType=result['platformType'],
                                                         threatType=result['threatType']).to_mongo())
            self.scanning_result.findings = GSBFindings.get_result_from_db(
                filter={'url': self.next_ooi_obj.ooi, 'findings': findings},
                ooi=None,
                scanner_obj=self,
                set_on_insert_dict={'finding_counter': len(findings)},
                only_id=True)
            self.scanning_result.finding_counter = len(findings)
