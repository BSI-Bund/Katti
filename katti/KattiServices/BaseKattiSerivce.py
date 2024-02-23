import datetime
import subprocess
import sys
import time
import traceback
from katti.DataBaseStuff.MongoengineDocuments.KattiServices.KattiServiceBaseDB import KattiServiceDB
from katti.KattiLogging.KattiLogging import setup_logger
from katti.KattiServices.DockerHealthCheckHTTPServer import DockerHealthCheckThread


class NotValidConfig(Exception):
    pass


class BaseKattiService:
    extra_python_libs: list[str] = []

    def __init__(self, env_vars):
        self.logger = setup_logger(name=env_vars['service_type'], level=env_vars['log_level'])
        self._heartbeat_interval = env_vars.get('heartbeat_interval', 60)
        self.sleep_time = 10
        self.docker_health_api_server: DockerHealthCheckThread = DockerHealthCheckThread()
        self.docker_status: str = 'unknown'
        self.db_document = None
        self.is_stop = False
        if env_vars.get('db_config_id'):
            self.db_document = self.db_config_cls.objects.get(id=env_vars['db_config_id'])
            self.reload_interval = env_vars.get('args_reload_interval', 60)
        self.env_vars = env_vars
        self._init()

    @property
    def db_config_cls(self):
        return KattiServiceDB

    def _init(self):
        pass

    def _next_control_round(self):
        raise NotImplementedError

    def shutdown(self):
        pass

    def prepare_service(self):
        pass

    @staticmethod
    def docker_init_stuff(*args, **init_args):
        pass

    def run(self):
        self.logger.debug('start')
        self.docker_status = 'ok'
        self.docker_health_api_server.start()
        try:
            self.logger.info('Prepare Service')
            self.prepare_service()
            self.logger.info('Start service work')
            while not self.is_stop:
                self._next_control_round()
                self.set_heartbeat_reload()
                self.sleep()
        except KeyboardInterrupt:
            pass
        except Exception:
            self.logger.exception(traceback.format_exception(*sys.exc_info()))
            self.docker_status = 'not_ok'
        finally:
            self.logger.info(f'Start shutdown: Is stop {self.is_stop}')
            self.shutdown()

    def set_heartbeat_reload(self):
        self.docker_health_api_server.set_status(new_status=self.docker_status)
        if self.db_document:
            self.db_document.reload_args(reload_interval=self.reload_interval)

    def sleep(self):
        start = datetime.datetime.utcnow()
        while (datetime.datetime.utcnow() - start).total_seconds() < self.sleep_time:
            time.sleep(1)
            self.set_heartbeat_reload()

    @classmethod
    def install_extra_libs(cls):
        for lib_name in cls.extra_python_libs:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--user', lib_name])
            except:
                pass

        import site
        from importlib import reload
        reload(site)
