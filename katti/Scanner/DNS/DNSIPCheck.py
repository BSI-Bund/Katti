import datetime
import sys
import traceback
from katti.Scanner.BaseScanner import OOI
from celery.result import AsyncResult
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import Ownership
from celery import group
from katti.KattiUtils.HelperFunctions import split
from katti.CeleryApps.ScanningTasks import dns_scanning_task
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSServerConfig import DNSConfig
from katti.Scanner.DNS.DNSResolver import DomainsForDNSResolverRequest


class DNSIPCheck:
    def __init__(self, domains: list[str], logger, meta_data_as_son, ownership: Ownership, scanner_name='google',
                 domains_per_domain_chunk=5, time_valid=0):
        self._logger = logger
        self._dns_task = group(dns_scanning_task.s(
            DomainsForDNSResolverRequest(oois=[OOI(raw_ooi=domain) for domain in domain_chunk],
                                         scanner_id=DNSConfig.objects.get(name=scanner_name).id,
                                         time_valid_response=time_valid,
                                         meta_data_as_son=meta_data_as_son,
                                         ownership_obj=ownership)) for domain_chunk in
                               split(domains, chunk_size=domains_per_domain_chunk)).apply_async(ignore_result=False)
        self.domains = domains
        self.nx_domains = []
        self.no_ip_domains = []
        self.ipv4 = {}
        self.ipv6 = {}

    @property
    def all_ips(self) -> set:
        ips = set()
        for key in self.ipv4:
            ips.update(self.ipv4[key])
        for key in self.ipv6:
            ips.update(self.ipv6[key])
        return ips

    def evaluate_dns_check(self, wait_time_for_task=15):
        if not self._dns_task:
            return
        try:
            start = datetime.datetime.utcnow()
            while (datetime.datetime.utcnow() - start).seconds < wait_time_for_task:
                if self._dns_task.ready():
                    break
            self._proof_dns_result(self._dns_task.results)
        except Exception:
            self._logger.exception(traceback.format_exception(*sys.exc_info()))

    def _proof_dns_result(self, dns_result_objects: list[AsyncResult]):
        dns_response_ids = []
        for asyn_result in dns_result_objects:
            match asyn_result.state:
                case 'SUCCESS':
                    for dns_result in asyn_result.result.results:
                        match dns_result['queries'][-1]['status']:
                            case 'NXDOMAIN':
                                self.nx_domains.append(dns_result['ooi'])
                                self.domains.remove(dns_result['ooi'])
                            case 'NOERROR':
                                dns_response_ids.append(dns_result['queries'][-1]['dns_response']['_id'])
                                if 'A_record' in dns_result['queries'][-1]['dns_response']:
                                    self.add_new_domain_ip_pair(self.ipv4, dns_result['ooi'],
                                                                dns_result['queries'][-1]['dns_response']['A_record'][
                                                                    'ip_str'])
                                if 'AAAA_record' in dns_result['queries'][-1]['dns_response']:
                                    self.add_new_domain_ip_pair(self.ipv6, dns_result['ooi'],
                                                                dns_result['queries'][-1]['dns_response'][
                                                                    'AAAA_record']['ip_str'])
                                self.no_ip_domains.append(dns_result['ooi'])
                                self.domains.remove(dns_result['ooi'])
                            case _:
                                pass

    def add_new_domain_ip_pair(self, ip_dict, domain, ip):
        if domain not in ip_dict:
            ip_dict.update({domain: {ip}})
        else:
            ip_dict[domain].add(ip)
