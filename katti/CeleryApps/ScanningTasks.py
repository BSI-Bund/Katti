import datetime
import logging
import pickle
import uuid
from random import randint
from typing import Type
import celery
from katti.DataBaseStuff.MongoengineDocuments.Scanner.LongTermRetry import LongTermRetryTask
from katti.KattiUtils.Configs.ConfigKeys import SCANNING_TASK_COUNTDOWN_SCANNER_STOP, SCANNING_TASKS_COUNTDOWN_DEFAULT
from katti.KattiUtils.Exceptions.ScannerExceptions import LongTermRetryException
from katti.Scanner.DNS.PTRScanner import IPsForPTR, PTRScanner
from katti.Scanner.DNS.SpamHaus import SpamHaus, IPsForSpamhaus
from katti.DataBaseStuff.MongoengineDocuments.Scanner.BaseMongoEngineDocument import ErrorParking
from katti.KattiUtils.Configs.pydanticStuff import PydanticConfig
from katti.RedisCacheLayer.RedisSignalHandler import RedisSignalHandling
from katti.Scanner.DNS.SinkDB import IPsForSinkDB, SinkDB
from katti.Scanner.TelekomPDNS.TelekomPDNS import TelekomPDNSRequest, TelekomPDNS
from katti.Scanner.MaxMindOffline.MaxMindOffline import IPsForMaxMind, MaxMindOffline
from pydantic import Field
from pydantic.dataclasses import dataclass
from katti.Scanner.AbuseIPDB.AbuseIPDB import AbuseIPDBScanner, AbuseIPDBIPs
from katti.Scanner.Farsight.Farsight import FarsightQuerries, Farsight
from katti.Scanner.SSLScanner.SSLScanner import DomainsForSSLScanningRequest, SSLScanner
from katti.Scanner.BaseScanner import RetryException, BaseScanner, BaseScanningRequestForScannerObject, \
    OfflineModeNoResult
from katti.Scanner.Shodan.Shodan import ShodanScanningRequest, ShodanScanner
from katti.Scanner.TeamCymru.TeamCymru import IPsForTeamCymru, TeamCymru
from katti.Scanner.TestScanner.TestScanner import TestRequest, TestScanner
from katti.Scanner.Traceroute.Traceroute import DomainsIpsTraceroute, Traceroute
from katti.Scanner.VirusTotal.VirusTotal import VirusTotal, IOCsForVTRequest
from katti.Scanner.GSB.GoogleSafeBrowsing import GoogleSafeBrowsing, URLsForGSBRequest
from katti.Scanner.DNS.DNSResolver import DNSResolver, DomainsForDNSResolverRequest
from bson import ObjectId
from katti.CeleryApps.KattiApp import katti_app
from katti.DataBaseStuff.MongoengineDocuments.StatisticDocuments.ScannerTaskStatistics import ScannerTaskStats
from katti.Scanner.Whois.Whois import Whois, WhoisRequest
from celery.exceptions import SoftTimeLimitExceeded, MaxRetriesExceededError


@dataclass(config=PydanticConfig)
class ScanningTaskResponse:
    scanner_id: ObjectId
    endpoint: str
    results: list = Field(default_factory=list)
    left_overs: list = Field(default_factory=list)
    offline_mode_no_results: list = Field(default_factory=list)


@dataclass(config=PydanticConfig)
class ExecutionInformation:
    task: celery.Task
    scanner: BaseScanner
    statistics: ScannerTaskStats
    logger: logging.Logger
    results: list
    request_obj: BaseScanningRequestForScannerObject

    @property
    def ignore_result(self) -> bool:
        return self.task.request.ignore_result


def get_task_id(task):
    task_id = task.request.id
    if not task_id:
        task_id = 'test'
    return task_id


def while_loop(execution_information: ExecutionInformation):
    response = ScanningTaskResponse(scanner_id=execution_information.scanner.scanner_document.id,
                                    endpoint=execution_information.task.name)
    next_ooi_obj = execution_information.request_obj.next_ooi_obj
    try:
        while next_ooi_obj:
            single_stats = ScannerTaskStats.SingleScannerStats(ooi=str(next_ooi_obj.ooi))
            start = datetime.datetime.utcnow()
            try:
                execution_information.scanner.scan(execution_information.request_obj, next_ooi=next_ooi_obj)
            except OfflineModeNoResult:
                response.offline_mode_no_results.append(execution_information.scanner.offline_get_failed_ooi_s)
            if execution_information.scanner.scanning_result and not execution_information.ignore_result:
                execution_information.results.append(
                    execution_information.scanner.scanning_result.get_complete_result())
            single_stats.duration_micro_secs = (datetime.datetime.utcnow() - start).microseconds
            execution_information.statistics.single_scan_ooi_stats.append(single_stats)
            next_ooi_obj = execution_information.request_obj.next_ooi_obj
    except RetryException:
        try:
            handle_retry_exception(execution_information, last_ooi_objc=next_ooi_obj,
                                   retry_args=execution_information.scanner.retry_args)
        except MaxRetriesExceededError:
            execution_information.scanner.max_retries_exceeded_handling()
            ErrorParking(oois=[ooi_objc.ooi for ooi_objc in execution_information.request_obj.oois],
                         katti_meta_data=execution_information.request_obj.meta_data_as_son,
                         ownership=execution_information.request_obj.ownership_as_son,
                         retry_counter=execution_information.task.request.retries,
                         max_retries=True,
                         scanning_request=pickle.dumps(execution_information.request_obj)).save()
            raise MaxRetriesExceededError()
    except LongTermRetryException:
        handle_long_term_retry_exception(execution_information, last_ooi_objc=next_ooi_obj,
                                         retry_args=execution_information.scanner.retry_args)
    except SoftTimeLimitExceeded:
        handle_normale_exception(execution_information)
    # except Exception:
    #    handle_normale_exception(execution_information)
    else:
        if execution_information.request_obj.long_term_retry_parent_task:
            LongTermRetryTask.objects(parent_task_id=execution_information.request_obj.long_term_retry_parent_task).update(__raw__={'$set': {'status': 'finished',
                                                                                                                                             'last_changed': datetime.datetime.utcnow()}})
        execution_information.logger.debug('Perfect, finished')
        response.results = execution_information.results
        response.left_overs = execution_information.request_obj.oois
        execution_information.statistics.oois_left_over = len(execution_information.request_obj.oois)
        execution_information.statistics.stop_and_save()
        return response


def handle_long_term_retry_exception(execution_information: ExecutionInformation, last_ooi_objc, retry_args: dict = {}):
    execution_information.request_obj.oois.append(last_ooi_objc)
    execution_information.statistics.oois_left_over = len(execution_information.request_obj.oois)
    execution_information.statistics.stop_and_save()
    retries = execution_information.task.request.retries + 1
    if execution_information.request_obj.max_day_retries < retries:
        LongTermRetryTask.objects(parent_task_id=execution_information.request_obj.long_term_retry_parent_task).updte(__raw__={'$set': {'last_changed': datetime.datetime.utcnow(), 'status': 'max_retries_exceeded'}})
        raise MaxRetriesExceededError()
    if not execution_information.request_obj.long_term_retry_parent_task:
        execution_information.request_obj.long_term_retry_parent_task = str(execution_information.task.request.id)
    new_signature = execution_information.task.signature_from_request(
        request=execution_information.task.request,
        args=(execution_information.request_obj, execution_information.results),
        retries=retries, **{'task_id': str(uuid.uuid4())})
    LongTermRetryTask.objects(parent_task_id=execution_information.request_obj.long_term_retry_parent_task).update(
        __raw__={'$setOnInsert': {'create': datetime.datetime.utcnow(), 'max_day_retries': execution_information.request_obj.max_day_retries},
                 '$set': {'status': 'pending',
                          'day_retries': retries,
                          'last_changed': datetime.datetime.utcnow(),
                          'next_execution': (datetime.datetime.utcnow() + datetime.timedelta(
                              seconds=retry_args.get('countdown', 86400))),
                          'task_signature': pickle.dumps(new_signature)}},
        upsert=True)
    raise LongTermRetryException('New long term retry is saved.')


def handle_retry_exception(execution_information: ExecutionInformation, last_ooi_objc, retry_args: dict = {}):
    execution_information.request_obj.oois.append(last_ooi_objc)
    execution_information.statistics.oois_left_over = len(execution_information.request_obj.oois)
    execution_information.statistics.stop_and_save()
    execution_information.task.retry(args=(execution_information.request_obj, execution_information.results),
                                     countdown=retry_args.get('countdown', randint(5, 600)))


def handle_normale_exception(execution_information: ExecutionInformation):
    execution_information.statistics.error = True
    execution_information.statistics.oois_left_over = len(execution_information.request_obj.oois)
    execution_information.statistics.stop_and_save()
    raise


def handle_soft_time_limit_exception(execution_information: ExecutionInformation):
    execution_information.statistics.error = True
    execution_information.statistics.task_timeout = True
    execution_information.statistics.oois_left_over = len(execution_information.request_obj.oois)
    execution_information.statistics.stop_and_save()


def set_up_and_execute_task(task: celery.Task, scanning_request, scanner_cls: Type[BaseScanner], results=None,
                            **kwargs):
    if results is None:
        results = []
    logger = logging.getLogger(
        f'{task.name}_{scanning_request.scanner_id}<:>{scanning_request.get_ownership_obj.owner}')
    scanner = scanner_cls(logger=logger, task=task)
    redis_signal = RedisSignalHandling(signal_id=str(task.name))
    if redis_signal.get_signal(RedisSignalHandling.STOP):
        logger.info(f'Stop signal is set, retry counter {task.request.retries}')
        task.retry(args=(scanning_request, results), countdown=SCANNING_TASK_COUNTDOWN_SCANNER_STOP)

    statistics = ScannerTaskStats.get_task_with_times(task_id=get_task_id(task),
                                                      scanner_task=task.name,
                                                      scanner_id=scanning_request.scanner_id,
                                                      retry_counter=task.request.retries,
                                                      initiator=scanning_request.get_ownership_obj.owner,
                                                      **kwargs.get('statistics', {}))

    scanner.set_up(scanning_request.scanner_id)
    return while_loop(ExecutionInformation(task=task, scanner=scanner,
                                           statistics=statistics, logger=logger, results=results,
                                           request_obj=scanning_request))


class BaseTaskWithRetry(celery.Task):
    max_retries = 3
    retry_backoff = True
    default_retry_delay = SCANNING_TASKS_COUNTDOWN_DEFAULT
    # soft_time_limit= 3*3600


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def dns_scanning_task(self, scanning_request: DomainsForDNSResolverRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=DNSResolver,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def gsb_scanning_task(self, scanning_request: URLsForGSBRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=GoogleSafeBrowsing,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def vt_scanning_task(self, scanning_request: IOCsForVTRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=VirusTotal,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def shodan_api_call_task(self, scanning_request: ShodanScanningRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=ShodanScanner,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def ssl_scanning_task(self, scanning_request: DomainsForSSLScanningRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=SSLScanner,
                                   results=results)


# @katti_app.task(bind=True)
# def misp_scanning_task(self, scanning_request: MISPScanningRequestObject, results=None, *args, **kwargs):
#    raise Exception


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def farsight_scanning_task(self, scanning_request: FarsightQuerries, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=Farsight, results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def traceroute_scanning_task(self, scanning_request: DomainsIpsTraceroute, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=Traceroute,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def team_cymru_scanning_task(self, scanning_request: IPsForTeamCymru, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=TeamCymru, results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def abuse_ip_db(self, scanning_request: AbuseIPDBIPs, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=AbuseIPDBScanner,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def maxmind(self, scanning_request: IPsForMaxMind, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=MaxMindOffline,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def telekom_api(self, scanning_request: TelekomPDNSRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=TelekomPDNS,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def whois_celery(self, scanning_request: WhoisRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=Whois, results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def sinkdb(self, scanning_request: IPsForSinkDB, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=SinkDB, results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def spamhaus(self, scanning_request: IPsForSpamhaus, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=SpamHaus, results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def ptr_scan(self, scanning_request: IPsForPTR, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=PTRScanner,
                                   results=results)


@katti_app.task(bind=True, base=BaseTaskWithRetry)
def test_scan_run(self, scanning_request: TestRequest, results: list | None = None, **kwargs):
    return set_up_and_execute_task(task=self, scanning_request=scanning_request, scanner_cls=TestScanner,
                                   results=results)
