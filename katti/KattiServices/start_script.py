import json
import signal
import sys
from pydoc import locate


from katti.KattiUtils.Configs.ConfigurationClass import set_up_env_vars, get_env_vars
from katti.RedisCacheLayer.Keys.Docker import service_init_kwargs
from katti.KattiUtils.Configs.Paths import KATTI_MASTER_CONFIG

set_up_env_vars()
env_vars = get_env_vars()
with open(KATTI_MASTER_CONFIG, 'w') as file:
    file.write(json.dumps({'key': env_vars['master_key'], 'base_url': env_vars['master_base_url']}))

from katti.RedisCacheLayer.RedisMongoCache import set_up_connection, RedisMongoCache
from katti.DataBaseStuff.ConnectDisconnect import context_manager_db
from katti.KattiServices.core_services.AddAppToSystem.AddAppToSystem import AddAppToSystem
from katti.KattiServices.core_services.BitsightStream.BitsightStream import BitsightStream
from katti.KattiServices.core_services.Certstream.Certstream import CalidogCerstream
from katti.KattiServices.core_services.CeleryEventStuff.CeleryEventStuff import CeleryEventStuff
from katti.KattiServices.core_services.MaxMindOfflineAPI.MaxMindAPIServer import APIService
from katti.KattiServices.core_services.MasterServer.MasterServer import MasterServer

service = None

def signal_handler(sig, frame):
    global service
    try:
        service.shutdown()
    except Exception:
        sys.exit(1)
    else:
        print('Shutdown')
        sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    with context_manager_db():
        set_up_connection()
        redis_cache = RedisMongoCache()
        docker_init_kwargs = redis_cache.get_value(service_init_kwargs(env_vars['service_type']), if_none={}, do_pickle=True)
        match env_vars['service_type']:
            case 'bitsight_stream':
                service = BitsightStream
            case 'ct_logs_stream':
                service = CalidogCerstream
            case 'add_extensions':
                service = AddAppToSystem
            case 'celery_event_stuff':
                service = CeleryEventStuff
            case 'maxmind':
                service = APIService
            case 'master':
                service = MasterServer
            case _:
                try:
                    service = locate(f'{env_vars["service_type"]}.{env_vars["service_type"]}.{env_vars["service_type"]}')
                except Exception:
                    sys.exit(2)
        service.docker_init_stuff(**docker_init_kwargs)
        service = service(env_vars)
        service.run()
