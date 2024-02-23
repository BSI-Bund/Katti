from katti.DataBaseStuff.MongoengineDocuments.Scanner.AbuseIPDB import AbuseIPDBDB
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSBL import SinkDB_DB, PTRConfig, SpamHausDB
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSServerConfig import DNSConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.FarsightDocument import FarsightDocument
from katti.DataBaseStuff.MongoengineDocuments.Scanner.GoogleSafeBrwosingConfig import GoogleSafeBrowserConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.MaxMindOffline import MaxMindOfflineDB
from katti.DataBaseStuff.MongoengineDocuments.Scanner.SSLScanner import SSLScannerDB
from katti.DataBaseStuff.MongoengineDocuments.Scanner.Shodan import ShodanScannerDB
from katti.DataBaseStuff.MongoengineDocuments.Scanner.TeamCymru import TeamCymruDB
from katti.DataBaseStuff.MongoengineDocuments.Scanner.TelekomPDNS import TelekomPDNSScannerConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.TracerouteConfig import TracerouteConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.VirusTotalConfig import VirusTotalConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.WhoisDB import WhoisDB
from katti.KattiUtils.Configs.ConfigKeys import DEFAULT_SYSTEM_QUEUE_PRIO
from katti.Scanner import SSL_SCANNER_ALLOWED_COMMANDS
from mongoengine import (ObjectIdField, StringField, ListField, EmbeddedDocument, IntField, \
    EmbeddedDocumentField, ValidationError, BooleanField, DictField)
from katti.DataBaseStuff.MongoengineDocuments.IntervalCronTab import Interval, CronTab


class BaseExecutionInformation(EmbeddedDocument):
    meta = {'allow_inheritance': True}

    max_lookups = IntField(default=1, min_value=0)
    priority = IntField(min_value=0, max_value=9, default=DEFAULT_SYSTEM_QUEUE_PRIO)
    queue = StringField(default=None)
    interval = EmbeddedDocumentField(Interval)
    cron_tab = EmbeddedDocumentField(CronTab)

    no_cron_or_int = BooleanField(default=None)


    def clean(self):
        if self.max_lookups == 1:
            self.interval = None
            self.cron_tab = None
            return
        if self.interval and self.cron_tab:
            msg = 'Cannot define both interval and crontab schedule.'
            raise ValidationError(msg)
        if not self.no_cron_or_int and not (self.interval or self.cron_tab) and not self.max_lookups == 1:
            msg = 'Must defined either interval or crontab schedule.'
            raise ValidationError(msg)

    def get_kwargs(self) -> dict:
        raise NotImplementedError


class BaseScannerExecutionInformation(BaseExecutionInformation):
    meta = {'allow_inheritance': True}
    scanner_id = ObjectIdField(required=True)
    time_valid_response = IntField(min_value=0, default=0)
    chunk_size = IntField(default=50)
    offline_mode = BooleanField(default=False)

    def set_default_scanner_id(self):
        raise NotImplementedError()

    def get_celery_task_object(self):
        #TODO: We need a meta base like method. (Conflic because of mongoengine Metaclass)
        raise NotImplementedError()

    __hash__ = hash(__name__)


class DNSExecutionInformation(BaseScannerExecutionInformation):
    dig_type = StringField(default='ANY')
    with_dnssec = BooleanField(default=False)

    def get_kwargs(self) -> dict:
        return {'dig_type': self.dig_type, 'with_dnssec': self.with_dnssec}

    def set_default_scanner_id(self):
        self.scanner_id = DNSConfig.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import dns_scanning_task
        return dns_scanning_task


class GSBExecutionInformation(BaseScannerExecutionInformation):

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = GoogleSafeBrowserConfig.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import gsb_scanning_task
        return gsb_scanning_task


class SSLScannerExecutionInformation(BaseScannerExecutionInformation):
    scan_command_strs = ListField(default=SSL_SCANNER_ALLOWED_COMMANDS)

    def get_kwargs(self) -> dict:
        return {'scan_command_strs': self.scan_command_strs}

    def set_default_scanner_id(self):
        self.scanner_id = SSLScannerDB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import ssl_scanning_task
        return ssl_scanning_task


class ShodanExecutionInformation(BaseScannerExecutionInformation):
    chunk_size = IntField(default=100, max_value=100)

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = ShodanScannerDB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import shodan_api_call_task
        return shodan_api_call_task


class VirusTotalExecutionInformation(BaseScannerExecutionInformation):
    endpoint = StringField(required=True)

    def get_kwargs(self) -> dict:
        return {'endpoint': self.endpoint}

    def set_default_scanner_id(self):
        self.scanner_id = VirusTotalConfig.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import vt_scanning_task
        return vt_scanning_task


class FarsightExecutionInformation(BaseScannerExecutionInformation):
    raw_querry = BooleanField(default=False)
    record_type = StringField(default='ANY')
    rdata_or_rrset = StringField(choices=['rdata_name', 'rdata_ip', 'rrset'], default='rrset')
    time_last_after = IntField()
    time_first_before = IntField()
    bailiwick = IntField()
    limit = IntField(min_value=1, max_value=30000, default=5000)

    def get_kwargs(self) -> dict:
        return {'raw_querry': self.raw_querry,
                'record_type': self.record_type,
                'rdata_or_rrset': self.rdata_or_rrset,
                'time_last_after': self.time_last_after,
                'time_first_before': self.time_first_before,
                'bailiwick': self.bailiwick,
                'limit': self.limit}

    def set_default_scanner_id(self):
        self.scanner_id = FarsightDocument.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import farsight_scanning_task
        return farsight_scanning_task


class TeamCymruExecutionInformation(BaseScannerExecutionInformation):
    chunk_size = IntField(default=50000)

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = TeamCymruDB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import team_cymru_scanning_task
        return team_cymru_scanning_task


class TracerouteExecutionInformation(BaseScannerExecutionInformation):

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = TracerouteConfig.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import traceroute_scanning_task
        return traceroute_scanning_task


class MaxMindExecutionInformation(BaseScannerExecutionInformation):
    db = StringField(choices=['asn', 'city', 'all'], default='all')

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = MaxMindOfflineDB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import maxmind
        return maxmind


class TelekomPassiveDNSScannerExecutionInformation(BaseScannerExecutionInformation):
    endpoint = StringField()

    def get_kwargs(self) -> dict:
        return {'endpoint': self.endpoint}

    def set_default_scanner_id(self):
        self.scanner_id = TelekomPDNSScannerConfig.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import telekom_api
        return telekom_api


class AbuseIPDBExecutionInformation(BaseScannerExecutionInformation):
    max_age_days = IntField(min_value=1, default=180)

    def get_kwargs(self) -> dict:
        return {'max_age_days': self.max_age_days}

    def set_default_scanner_id(self):
        self.scanner_id = AbuseIPDBDB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import abuse_ip_db
        return abuse_ip_db


class WhoisExecutionInformation(BaseScannerExecutionInformation):
    whois_server = StringField()

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = WhoisDB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import whois_celery
        return whois_celery


class SinkDBExecutionInformation(BaseScannerExecutionInformation):

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = SinkDB_DB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import sinkdb
        return sinkdb


class PTRRecordExecutionInformation(BaseScannerExecutionInformation):

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = PTRConfig.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import ptr_scan
        return ptr_scan


class ZenspamhausExecutionInformation(BaseScannerExecutionInformation):

    def get_kwargs(self) -> dict:
        return {}

    def set_default_scanner_id(self):
        self.scanner_id = SpamHausDB.get_default_scanner_id()

    def get_celery_task_object(self):
        from katti.CeleryApps.ScanningTasks import spamhaus
        return spamhaus


class ScanningTaskChaining(BaseExecutionInformation):
    kwargs_for_building = DictField()
    celery_workflow_build_func = StringField(required=True)

    def start_workflow_builder(self, **addional_kwargs):
        from katti.CeleryApps.Workflows import BuilderMapping
        self.kwargs_for_building.update(addional_kwargs)
        BuilderMapping[self.celery_workflow_build_func].value(**self.kwargs_for_building)


def get_scanner_execution_info_from_dict(info_as_dict: dict):
    from katti.DataBaseStuff.MongoengineDocuments import ScannerExecutionInformation
    scanner_info_cls = info_as_dict['_cls'].replace('BaseExecutionInformation.BaseScannerExecutionInformation', '')
    scanner_cls = getattr(ScannerExecutionInformation, scanner_info_cls)
    return scanner_cls(**info_as_dict)


