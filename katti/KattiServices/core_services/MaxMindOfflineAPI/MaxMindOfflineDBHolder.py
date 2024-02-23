import datetime
import logging
import os
import shutil
import tarfile
import threading
from dataclasses import dataclass, field
from io import BytesIO
import geoip2.database
import requests
from geoip2.errors import AddressNotFoundError
from croniter import croniter


max_mind_db_file_path= lambda db_name: os.path.expanduser(f'~/max_mind_db_file_{db_name}')


class DBIsNotReady(Exception):
    pass


CRON_DOWNLOAD = '0 4 * * *'
LICENSE_KEY = None


def set_key(key):
    global LICENSE_KEY
    LICENSE_KEY = key


@dataclass
class DBFileHolder:
    db_type: str
    logger: logging.Logger
    max_mind_cursor: geoip2.database.Reader | None = None
    last_update: datetime.datetime | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


    def up_to_date(self) -> bool:
        global CRON_DOWNLOAD
        if not self.last_update or croniter(CRON_DOWNLOAD, datetime.datetime.utcnow()).get_next(datetime.datetime) < self.last_update:
            self._download_maxmind_from_internet()

    def _download_maxmind_from_internet(self):
        response = requests.get(url=f'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-{self.db_type}&license_key={LICENSE_KEY}&suffix=tar.gz')
        match response.status_code:
            case 200:
                self.logger.debug('Valid response, prepare new db file')
                self._extract_db_file(response.content)
            case _:
                self.logger.error(f'Bad status code: {response.status_code} {response.text}. Use the old db file.')

    def _extract_db_file(self, raw_file):
        if os.path.exists(max_mind_db_file_path(self.db_type)):
            shutil.rmtree(max_mind_db_file_path(self.db_type), ignore_errors=True)
        tar = tarfile.open(fileobj=BytesIO(raw_file))
        for member in tar.getmembers():
            if '.mmdb' in member.name:
                tar_file = tar.extractfile(member)
                with open(max_mind_db_file_path(self.db_type), 'w+b') as file:
                    file.write(tar_file.read())
                break
        self.max_mind_cursor = geoip2.database.Reader(max_mind_db_file_path(self.db_type))
        self.last_update = datetime.datetime.utcnow()

    def check_ip(self, ip):
        match self.db_type:
            case 'Country':
                resp_co = self.max_mind_cursor.country(ip)
                return self._produce_db_response(resp_co)
            case 'City':
                resp_co = self.max_mind_cursor.city(ip)
                return self._produce_db_response(resp_co)
            case 'ASN':
                return self.max_mind_cursor.asn(ip).__dict__['raw']

    def _produce_db_response(self, db_response):
        result = {}
        try:
            country_dict = db_response.country.__dict__
            del country_dict['_locales']
            del country_dict['names']
            result.update({'country': country_dict})
        except Exception:
            pass
        try:
            continent_dict = db_response.continent.__dict__
            del continent_dict['_locales']
            del continent_dict['names']
            result.update({'continent': continent_dict})
        except Exception:
            pass
        try:
            represented_country = db_response.represented_country.__dict__
            del represented_country['_locales']
            del represented_country['names']
            result.update({'represented_country': represented_country})
        except Exception:
            pass
        try:
            registered_country = db_response.registered_country.__dict__
            del registered_country['_locales']
            del registered_country['names']
            result.update({'registered_country': registered_country})
        except Exception:
            pass
        try:
            traits = db_response.traits.__dict__
            result.update({'traits': traits})
        except Exception:
            pass
        try:
            loaction = db_response.location.__dict__
            result.update({'location': loaction})
        except Exception:
            pass
        try:
            postal = db_response.postal.__dict__
            result.update({'postal': postal})
        except Exception:
            pass
        try:
            subdiv = []
            for sub_div in db_response.subdivisions:
                x = sub_div.__dict__
                del x['_locales']
                x.update({'name': x['names']['en']})
                del x['names']
                subdiv.append(x)
            result.update({'subdivisions': subdiv})
        except Exception:
            pass

        try:
            city = db_response.city.__dict__
            del city['_locales']
            city.update({'name': city['names']['en']})
            del city['names']
            result.update({'city': city})
        except Exception:
            pass
        return result


class MaxMindDBHolder:
    def __init__(self):
        logger = logging.getLogger()
        logger.addHandler(logging.StreamHandler())
        self._max_mind_country_db: DBFileHolder = DBFileHolder(db_type='Country', logger=logger)
        self._max_mind_city_db: DBFileHolder = DBFileHolder(db_type='City', logger=logger)
        self._max_mind_asn_db: DBFileHolder = DBFileHolder(db_type='ASN', logger=logger)

    def get_country_for_ips(self, ips: list):
        return self._check(ips, self._max_mind_country_db)

    def get_city_for_ips(self, ips: list):
        return self._check(ips, self._max_mind_city_db)

    def get_asn_for_ips(self, ips: list):
        return self._check(ips, self._max_mind_asn_db)

    def _check(self, ips, db_holder: DBFileHolder):
        answer = []
        with db_holder.lock:
            db_holder.up_to_date()
            if not db_holder.max_mind_cursor:
                raise DBIsNotReady()
            for ip in ips:
                try:
                    answer.append([ip, db_holder.check_ip(ip)])
                except AddressNotFoundError:
                    answer.append([ip, {'error': {'reason': 'AddressNotFoundError', 'db': db_holder.db_type}}])
                except Exception:
                    answer.append([ip, {'error': {'reason': 'Unknown', 'db': db_holder.db_type}}])
            return answer