import datetime
import ipaddress
import pickle
import socket
import typing
from katti.DataBaseStuff.MongoengineDocuments.Common.Link import IP, CIDR
from pydantic import Field, field_validator
from pydantic.dataclasses import dataclass
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import BaseScanningRequests, \
    BaseScannerDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.TeamCymru import TeamCymruRequest, TeamCymruDB, TeamCymruResult
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    TeamCymruExecutionInformation
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.Scanner.BaseScanner import BaseScanner, BaseScanningRequestForScannerObject, OOI


@dataclass(config=PydanticConfig)
class TeamCymruOOI(OOI):
    raw_ooi: list[typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = Field(default_factory=list, min_items=1, max_items=50000)

    @property
    def ooi(self):
        return self.raw_ooi


@dataclass(config=PydanticConfig)
class IPsForTeamCymru(BaseScanningRequestForScannerObject):

    @field_validator('oois')
    def check_oois(cls, v):
        if len(v) > 1 or len(v) == 0:
            raise ValueError('Only one TeamCymruOOI are allowed, but min. 1.')
        if not isinstance(v[0], TeamCymruOOI):
            raise ValueError('Only TeamCymruOOI are allowed.')
        return v

    @staticmethod
    def ooi_cls():
        return TeamCymruOOI

    @staticmethod
    def build_ooi_objects(raw_oois: list[typing.Any]) -> list[OOI]:
        return [TeamCymruOOI(raw_ooi=[ipaddress.ip_address(ip) for ip in raw_oois])]

    @property
    def quota_amount(self) -> int:
        return 1

    @staticmethod
    def can_handle_ooi_type(ooi_type: str) -> bool:
        match ooi_type:
            case 'ips' | 'ipv4' | 'ipv6':
                return True
            case _:
                return False


class TeamCymru(BaseScanner):
    scanning_request: IPsForTeamCymru
    scanning_result: TeamCymruRequest

    @classmethod
    def get_celery_config(cls) -> [BaseScanningRequestForScannerObject, callable]:
        from katti.CeleryApps.ScanningTasks import team_cymru_scanning_task
        return [IPsForTeamCymru, team_cymru_scanning_task]

    @classmethod
    def pre_defined_config_for_ooi_type(cls, scanner_name: str, ooi_type: str) -> dict[str:dict[str:str]]:
        return super().pre_defined_config_for_ooi_type(scanner_name, ooi_type)

    @classmethod
    def get_scanner_execution_information(cls) -> BaseScannerExecutionInformation:
        return TeamCymruExecutionInformation

    @staticmethod
    def get_scanner_type() -> str:
        return 'team_cymru'

    @classmethod
    def add_scanner_to_system_stuff(self, config: dict) -> BaseScannerDocument:
        return TeamCymruDB(**config)

    @staticmethod
    def get_result_class() -> typing.Union[BaseScannerDocument]:
        return TeamCymruRequest

    @staticmethod
    def get_scanner_mongo_document_class():
        return TeamCymruDB

    @property
    def bulk_scanner(self) -> bool:
        return True

    def convert_ooi_to_db_type(self):
        self.ip_list_str = []
        self._redis_valid_result_ids = []
        self._rest_ips = []
        for ip in self.next_ooi_obj.ooi:
            self.ip_list_str.append(str(ip))
            result_id = self._check_is_valid_result_in_redis(ip)
            if result_id:
                self._redis_valid_result_ids.append(result_id)
            else:
                self._rest_ips.append(ip)
        return self.ip_list_str

    def _check_is_valid_result_in_redis(self, ip_str):
        cache = self.redis_cache.get_value(f'cymru{ip_str}')
        if cache:
            cache = pickle.loads(cache)
        if not cache or (datetime.datetime.utcnow() - cache['time']).total_seconds() > self.scanning_request.time_valid_response:
            return None
        return cache['id']

    def _do_your_scanning_job(self):
        start_str = 'begin\nverbose\n'
        end_str = 'end'
        if len(self._rest_ips) > 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('whois.cymru.com', 43))
                response = b''
                for ip in self._rest_ips:
                    start_str += f'{ip}\n'
                start_str += end_str
                sock.send(start_str.encode())
                sock.settimeout(2)
                while True:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            break
                        self.logger.debug(f'Data leng.: {len(data)}')
                        response += data
                    except socket.timeout:
                        self.logger.debug('Socket timeout')
                        break
            response = response.decode()
            for line in response.splitlines()[1:]:
                if 'Error' in line:
                    try:
                        self.scanning_result.entries.append(
                            TeamCymruResult.get_result_from_db(scanner_obj=self, ooi=None, filter={
                                'error_ip': self.next_ooi_obj.ooi[int(line.replace('.', '').split(' ')[8]) - 3]}, only_id=True))
                    except Exception:
                        self.logger.error(f'Something is wrong:\n{line}')
                    continue
                line_p = line.split('|')
                if not len(line_p) == 7:
                    self.logger.error(f'Something is wrong:\n{line}')
                    continue
                ip_adr = IP.build_from_ip_str(ip_str=line_p[1].replace(' ', '')).to_mongo()
                cidr = CIDR.build_from_cidr(cidr_str=line_p[2].replace(' ', '')).to_mongo()
                filter = {'asn_numer': line_p[0].replace(' ', ''),
                          'ip_adr.ip_number': ip_adr.get('ip_number'),
                          'cidr.cidr_str': cidr.get('cidr_str'),
                          'country_code': line_p[3].replace(' ', ''),
                          'registry': line_p[4].rstrip().lstrip(),
                          'allocated': line_p[5].replace(' ', ''),
                          'asn_name': line_p[6].rstrip()}
                self.scanning_result.entries.append(
                    TeamCymruResult.get_result_from_db(scanner_obj=self, ooi=None, filter=filter,
                                                       update={'$setOnInsert': {'ip_adr': ip_adr,
                                                                                'cidr': cidr}}, only_id=True))
                for result in self.scanning_result.entries:
                    self.redis_cache.insert_value_pair(f'cymru{ip_adr["ip_str"]}', pickle.dumps({'id': result.id,
                                                                                                 'time': datetime.datetime.utcnow()}), ttl=24*3600)

            self.scanning_result.entries.extend(self._redis_valid_result_ids)

    def offline_mode(self):
        self._build_scanning_result()
        ips = set()
        for ip in self.next_ooi_obj.ooi:
            ips.add(str(ip))
        self.scanning_result.entries = [entry.id for entry in TeamCymruResult.objects(ip_adr__ip_str__in=list(ips))]
