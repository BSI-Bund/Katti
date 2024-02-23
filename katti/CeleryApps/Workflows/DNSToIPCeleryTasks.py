import importlib
import inspect
import ipaddress
from dataclasses import dataclass, field
from celery import group, chord
from bson import ObjectId
from celery.canvas import Signature

from katti.CeleryApps.KattiApp import katti_app
from katti.CeleryApps.ScanningTasks import ScanningTaskResponse
from katti.CeleryApps.Utilis import build_celery_scanning_task_from_execution_information
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSServerConfig import DNSRequest
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import get_scanner_execution_info_from_dict
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import Ownership, MetaData
from katti.KattiUtils.HelperFunctions import split
from katti.Scanner.BaseScanner import BaseScanner, Backpropagation
from katti.Scanner.Helpers import get_backpropagation_results


@dataclass
class IPResult:
    ipv4: set = field(default_factory=set)
    ipv6: set = field(default_factory=set)
    ipv4_id_mapping: dict = field(default_factory=dict)
    ipv6_id_mapping: dict = field(default_factory=dict)

    dns_result_ids: list[ObjectId] = field(default_factory=list)

    _all_ips: set[ipaddress.ip_address] = field(default_factory=set)
    _all_mapping: dict = field(default_factory=dict)

    @property
    def get_all_ips(self):
        if len(self._all_ips) == 0:
            self._all_ips.update(self.ipv4)
            self._all_ips.update(self.ipv6)
        return self._all_ips


    @property
    def get_all_mapping(self):
        if len(self._all_mapping) == 0:
            self._all_mapping = self.ipv4_id_mapping
            self._all_mapping.update(self.ipv6_id_mapping)
        return self._all_mapping


@katti_app.task(bind=True)
def ip_scanner_after_dns(self, ip_results: IPResult, owner_ship_id: ObjectId, ip_scanner_infos: list[dict],
                         meta_data: MetaData | None = None, after_ip_scanner_task_function = None):
    ownership = Ownership(owner=owner_ship_id)
    group_tasks = []

    for scanner_info in ip_scanner_infos:
        scanner_info_obj = get_scanner_execution_info_from_dict(scanner_info)
        celery_task, request_cls = build_celery_scanning_task_from_execution_information(execution_information=scanner_info_obj, ownership=None, meta_data=None, oois=None, get_only_task=True)

        scanner_module = importlib.import_module(request_cls.__module__)
        module_file = inspect.getmembers(scanner_module,
                                         lambda x: inspect.isclass(x)
                                                   and not x == BaseScanner and issubclass(x, BaseScanner))
        scanner_type = module_file[0][1].get_scanner_type()

        if request_cls.can_handle_ooi_type('ips'):
            ips = ip_results.get_all_ips
            ip_id_mapping = ip_results.get_all_mapping
        elif request_cls.can_handle_ooi_type('ipv4'):
            ips = ip_results.ipv4
            ip_id_mapping = ip_results.ipv4_id_mapping
        else:
            ips = ip_results.ipv6
            ip_id_mapping = ip_results.ipv6_id_mapping

        backwards_propagation = [Backpropagation(collection=DNSRequest._meta['collection'],
                                                 id_ooi_mapping=ip_id_mapping,
                                                 field_name=scanner_type)]
        for chunk in split(list(ips), chunk_size=scanner_info_obj.chunk_size):
            x = build_celery_scanning_task_from_execution_information(execution_information=scanner_info_obj,
                                                                      ownership=ownership,
                                                                      meta_data=meta_data,
                                                                      oois=chunk,
                                                                      backwards_propagation=backwards_propagation)
            x.set(ignore_result=self.request.ignore_result if not after_ip_scanner_task_function else False)
            group_tasks.append(x)
    if len(group_tasks) > 0:
        if after_ip_scanner_task_function:
            return chord(header=group_tasks, body=after_ip_scanner_task_function.s(kwargs={'ip_results': ip_results})).apply_async()
        if not self.request.ignore_result:
            return chord(header=group_tasks, body=extract_dns_results_with_extra_scanners.s(dns_results=ip_results)).apply_async()
        else:
            return group(group_tasks).apply_async()
    return None



@katti_app.task(bind=True)
def extract_ips_from_dns_results(self, dns_source_results: ScanningTaskResponse):
    ip_result = IPResult()

    for dns_result in dns_source_results.results:
        ip_result.dns_result_ids.append(dns_result['_id'])
        try:
            records = dns_result['queries'][-1]['records']
        except (KeyError, IndexError):
            continue
        for record in records:
            if record['record_type'] == 'A':
                try:
                    ip_result.ipv4.add(record['ip_str'])
                    if record['ip_str'] in ip_result.ipv4_id_mapping:
                        ip_result.ipv4_id_mapping[record['ip_str']].append(dns_result['_id'])
                    else:
                        ip_result.ipv4_id_mapping.update({record['ip_str']: [dns_result['_id']]})
                except Exception:
                    pass
                continue
            if record['record_type'] == 'AAAA':
                try:
                    ip_result.ipv6.add(record['ip_str'])
                    if record['ip_str'] in ip_result.ipv6_id_mapping:
                        ip_result.ipv6_id_mapping[record['ip_str']].append(dns_result['_id'])
                    else:
                        ip_result.ipv6_id_mapping.update({record['ip_str']: [dns_result['_id']]})
                except Exception:
                    pass
                continue
    return ip_result
