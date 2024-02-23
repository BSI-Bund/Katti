import json
import signal
import sys

from katti.KattiServices.core_services.MasterServer.MasterServer import MasterServer
from katti.KattiUtils.Configs.ConfigurationClass import set_up_env_vars, get_env_vars
from katti.KattiUtils.Configs.Paths import KATTI_MASTER_CONFIG


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
    set_up_env_vars()
    env_vars = get_env_vars()
    master = MasterServer(env_vars)
    master.start()