from katti.DataBaseStuff.ConnectDisconnect import context_manager_db
from katti.Scanner.DNS.DNSResolver import DomainsForDNSResolverRequest
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSServerConfig import DNSConfig
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.Tag import Ownership
from katti.CeleryApps.ScanningTasks import dns_scanning_task
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.TimeLord import TimeLord


if __name__ == '__main__':
    with context_manager_db():
        owner = TimeLord.get_system_user_id()
        task = dns_scanning_task.s(DomainsForDNSResolverRequest(
            oois=DomainsForDNSResolverRequest.build_ooi_objects(raw_oois=["google.com"]),
            dig_type="ANY",
            dig_flags=[],
            scanner_id=DNSConfig.get_default_scanner_id(),
            ownership_obj=Ownership(owner=owner)
        ))
        result = task.apply_async()
        print(result.get())
