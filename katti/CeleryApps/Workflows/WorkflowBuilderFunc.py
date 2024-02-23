from dataclasses import dataclass
from typing import Any

from bson import ObjectId
from celery import chain, group
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation, \
    DNSExecutionInformation
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import Ownership, MetaData
from katti.KattiUtils.HelperFunctions import split
from katti.CeleryApps.ScanningTasks import dns_scanning_task
from katti.Scanner.DNS.DNSResolver import DomainsForDNSResolverRequest
from katti.CeleryApps.Workflows.DNSToIPCeleryTasks import ip_scanner_after_dns, extract_ips_from_dns_results


@dataclass
class DNSTOIPConfig:
    owner_id: ObjectId
    dns_settings: DNSExecutionInformation
    ip_scanner_infos: list[BaseScannerExecutionInformation]
    domains: list[str]
    wait_for_result: bool = False
    max_wait_time_for_result: int = 60
    meta_data: dict | None = None
    after_ip_scanner_celery_task: Any | None = None


def dns_to_ip_scanner_workflow_builder(dns_ip_config: DNSTOIPConfig, **kwargs):
    ownership = Ownership(owner=dns_ip_config.owner_id)
    meta_data = None
    chain_tasks = []
    if dns_ip_config.meta_data:
        meta_data = MetaData(**dns_ip_config.meta_data)

    dns_scanner_id = dns_ip_config.dns_settings.scanner_id
    for chunk in split(dns_ip_config.domains, dns_ip_config.dns_settings.chunk_size):
        dns_task = dns_scanning_task.s(
            DomainsForDNSResolverRequest(oois=DomainsForDNSResolverRequest.build_ooi_objects(chunk),
                                         ownership_obj=ownership,
                                         meta_data_obj=meta_data,
                                         offline=dns_ip_config.dns_settings.offline_mode,
                                         time_valid_response=dns_ip_config.dns_settings.time_valid_response,
                                         scanner_id=dns_scanner_id))
        dns_task.set(priority=dns_ip_config.dns_settings.priority)
        if dns_ip_config.dns_settings.queue:
            dns_task.set(queue=dns_ip_config.dns_settings.queue)
        ip_scanner_after_dns_task = ip_scanner_after_dns.s(owner_ship_id=dns_ip_config.owner_id,
                                                           meta_data=meta_data,
                                                           ip_scanner_infos=[x.to_mongo() for x in
                                                                             dns_ip_config.ip_scanner_infos])
        ip_scanner_after_dns_task.set(ignore_result=not dns_ip_config.wait_for_result)
        new_chain = chain(dns_task, extract_ips_from_dns_results.s(), ip_scanner_after_dns_task)
        chain_tasks.append(new_chain)
    if kwargs.get('only_chains'):
        return chain_tasks

    group_task = group(chain_tasks)
    group_task = group_task.apply_async()
    if dns_ip_config.wait_for_result:
        result = group_task.get(timeout=dns_ip_config.max_wait_time_for_result)
        return [re for x in result for re in x.get()]
    return group_task
