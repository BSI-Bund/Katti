import datetime
import logging
import threading
import time
from katti.CeleryApps.Workflows.WorkflowBuilderFunc import dns_to_ip_scanner_workflow_builder, DNSTOIPConfig
from katti.DataBaseStuff.ConnectDisconnect import connect_to_database
from katti.DataBaseStuff.MongoengineDocuments.KattiServices.CalidogCertStream import CalidogCerstreamEntry
from katti.DataBaseStuff.MongoengineDocuments.Scanner.DNSServerConfig import DNSConfig
from katti.DataBaseStuff.MongoengineDocuments.Scanner.MaxMindOffline import MaxMindOfflineDB
from katti.DataBaseStuff.MongoengineDocuments.ScannerExecutionInformation import MaxMindExecutionInformation, \
    DNSExecutionInformation
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.TimeLord import TimeLord
from katti.KattiServices.BaseKattiSerivce import BaseKattiService
from katti.KattiServices.core_services.Certstream.CertStreamClient import ThreadData, listen_for_events
from katti.KattiUtils.HelperFunctions import is_valid_domain


class CalidogCerstream(BaseKattiService):

    def _next_control_round(self):
        if self._certstream_client_data.entry_list_len > 0:
            bulk_ops = self._certstream_client_data.get_list_and_reset()
            CalidogCerstreamEntry._get_collection().bulk_write(bulk_ops)
            if self.env_vars.get('do_scanner', True):
                self._next_domain = None
                raw_domains = set([self._next_domain for op in bulk_ops for domain in op._doc['leaf_cert']['all_domains'] if self._help_check(domain)])
                self._build_scanner_tasks(raw_domains)

        time.sleep(self.env_vars.get('time_sleep', 5))

    def _help_check(self, domain):
        self._next_domain = None
        if '*' in domain and self.env_vars.get('with_wildcards', True):
            self._next_domain = domain.replace('*.', '')
        elif not '*' in domain:
            self._next_domain = domain
        if self._next_domain and is_valid_domain(self._next_domain):
            return True
        return False

    def _build_scanner_tasks(self, domains):
        owner_id = TimeLord.get_system_user_id()
        meta_data = {'origin': 'ct_logs'}
        dns = DNSConfig.get_default_scanner_id()
        maxmind = MaxMindExecutionInformation(scanner_id=MaxMindOfflineDB.get_default_scanner_id(),
                                              priority=1)
        dns_ip_config = DNSTOIPConfig(owner_id=owner_id,
                                      domains=domains,
                                      ip_scanner_infos=[maxmind],
                                      meta_data=meta_data,
                                      dns_settings=DNSExecutionInformation(scanner_id=dns,
                                                                           priority=1,
                                                                           with_dnssec=True))

        dns_to_ip_scanner_workflow_builder(dns_ip_config=dns_ip_config)

    def shutdown(self):
        self._certstream_client_data.stop_event.set()
        self.logger.info('Wait for shutdown of thread.')
        start = datetime.datetime.utcnow()
        while (datetime.datetime.utcnow() - start).total_seconds() < self.env_vars.get('wait_shutdown', 7) and self._certstream_client_thread.is_alive():
            time.sleep(0.2)

    def _init(self):
        self._X509LogEntry = self.env_vars.get('X509LOGENTRY', True)
        self._PrecertLogEntry = self.env_vars.get('PrecertLogEntry', False)
        self._certstream_url = self.env_vars.get('URL', 'wss://certstream.calidog.io/')

    def prepare_service(self):
        self._certstream_client_data = ThreadData(X509LogEntry=self._X509LogEntry,
                                                  PrecertLogEntry=self._PrecertLogEntry)
        self._certstream_client_thread = threading.Thread(target=listen_for_events, args=(self._certstream_url,
                                                                                          self.logger.getChild('certstream_client'),
                                                                                          self._certstream_client_data))
        self.logger.info('Start cerstream client.')
        self._certstream_client_thread.start()
        self._certstream_client_data.is_x_509_log_entry = self._X509LogEntry
        self._certstream_client_data.is_precert_log_entry = self._PrecertLogEntry



if __name__ == '__main__':
    connect_to_database()
    x = CalidogCerstream(env_vars={'service_type': 'ct_logs_stream', 'log_level': logging.DEBUG})
    x.run()