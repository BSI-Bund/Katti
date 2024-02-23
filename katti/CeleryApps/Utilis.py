from katti.KattiUtils.Exceptions.CommonExtensions import UnknownInputType
from katti.KattiUtils.HelperFunctions import is_valid_ip_v4_or_v6
from pydantic.dataclasses import dataclass
from pydantic import Field
from inspect import signature
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import Ownership, MetaData
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import BaseScannerExecutionInformation


@dataclass
class Input:
    """ipv4,ipv6,ips,domain,url,object_id,sha_256"""
    ipv4: set = Field(default_factory=set)
    ipv6: set = Field(default_factory=set)
    ips: set = Field(default_factory=set)
    domains: set = Field(default_factory=set)
    urls: set = Field(default_factory=set)
    object_ids: set = Field(default_factory=set)
    sha_256: set = Field(default_factory=set)

    def get_all_ois(self) -> list:
        x = []
        x.extend(list(self.ips))
        x.extend(list(self.domains))
        x.extend(list(self.urls))
        x.extend(list(self.object_ids))
        x.extend(list(self.sha_256))
        return x

    def add_new_ooi(self, ooi, ooi_type: str):
        #TODO: Check ooi and type match
        match ooi_type:
            case 'ips' | 'ipv4' | 'ipv6':
                if ooi is isinstance(ooi, (list, set)):
                    for ip in ooi:
                        self._add_ip(ip)
                else:
                    self._add_ip(ooi)
            case 'url':
                self._add(self.urls, ooi)
            case 'domain':
                self._add(self.domains, ooi)
            case 'object_id':
                self._add(self.object_ids, ooi)
            case 'sha_256':
                self._add(self.sha_256, ooi)
            case _:
                raise UnknownInputType(ooi_type)
        return self

    def _add_ip(self, ip):
        match is_valid_ip_v4_or_v6(ip):
            case 4:
                self._add(self.ipv4, ip)
                self._add(self.ips, ip)
            case 6:
                self._add(self.ipv6, ip)
                self._add(self.ips, ip)
            case 0:
                pass

    def _add(self, attribute, data):
        if isinstance(data, (list, set)):
            attribute |= data
        else:
            attribute.add(data)



    def get_oois(self, ooi_type):
        match ooi_type:
            case 'ipv4':
                return list(self.ipv4)
            case 'ipv6':
                return list(self.ipv6)
            case 'ips':
                return list(self.ips)
            case 'urls':
                return list(self.urls)
            case 'domains':
                return list(self.domains)
            case 'object_ids':
                return list(self.object_ids)
            case 'sha_256':
                return list(self.sha_256)
            case _:
                raise UnknownInputType(ooi_type)


def build_celery_scanning_task_from_execution_information(execution_information: BaseScannerExecutionInformation, ownership:
Ownership, meta_data: MetaData, oois, get_only_task: bool = False, backwards_propagation=None, **kwargs):
    if not backwards_propagation:
        backwards_propagation = []
    celery_task = execution_information.get_celery_task_object()
    if get_only_task:
        return celery_task, signature(celery_task).parameters['scanning_request'].annotation
    else:
        request_cls = signature(celery_task).parameters['scanning_request'].annotation
        kwargs.update(execution_information.get_kwargs())
        task = celery_task.s(request_cls.build_request(raw_oois=oois,
                                                       ownership=ownership,
                                                       meta_data=meta_data,
                                                       backwards_propagation=backwards_propagation,
                                                       offline_mode=execution_information.offline_mode,
                                                       time_valid_response=execution_information.time_valid_response,
                                                       scanner_id=execution_information.scanner_id,
                                                       **kwargs))
        task.set(priority=execution_information.priority)
        if execution_information.queue:
            task.set(queue=execution_information.queue)
        return task
