import subprocess
import typing
import katti.jc as jc
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    TracerouteExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.Helpers import preexec_function
from katti.KattiUtils.HelperFunctions import is_valid_domain, is_ip_addr_valid
from pydantic import field_validator
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.TracerouteConfig import TracerouteAnswer, TracerouteConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI


@dataclass(config=PydanticConfig)
class TracerouteOOI(OOI):
    #TODO: Ähm ja, hier sollte noch irgendwie ein etwas ausgereifter Check hin...

    @field_validator('raw_ooi')
    def validate_ooi(cls, v):
        if not is_valid_domain(v) and not is_ip_addr_valid(v):
            raise ValueError('Only domains or IPs are allowed.')
        else:
            return v


@dataclass(config=PydanticConfig)
class DomainsIpsTraceroute(BaseScanningRequestForScannerObject):

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [TracerouteOOI(raw_ooi=ip_or_domain) for ip_or_domain in raw_oois]

    @staticmethod
    def ooi_cls():
        return TracerouteOOI

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


class Traceroute(BaseScanner):
    scanner_document: TracerouteConfig

    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import traceroute_scanning_task
        return [DomainsIpsTraceroute, traceroute_scanning_task]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return TracerouteExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'traceroute'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return TracerouteConfig(**config)

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return TracerouteAnswer

    @staticmethod
    def get_scanner_mongo_document_class():
        return TracerouteConfig

    def _do_your_scanning_job(self):
        try:
            cmd_output = subprocess.check_output(['traceroute', '-I', f'{self.next_ooi_obj.ooi}'], preexec_fn=preexec_function,
                                                 text=True)
        except Exception as e:
            self.scanning_result.traceroute_exc = f'{e}'
        else:
            result = jc.parse('traceroute', cmd_output)
            hops = []
            for hop in result['hops']:
                if len(hop['probes']) > 0:
                    hops.append(hop)
            self.scanning_result.hops = hops
            self.scanning_result.hops_counter = len(hops)
            self.scanning_result.destination_ip = result['destination_ip']
