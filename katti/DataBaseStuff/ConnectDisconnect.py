from contextlib import contextmanager

from mongoengine import connect, disconnect
from katti.KattiUtils.Configs.ConfigurationClass import DatabaseConfigs


CFG: DatabaseConfigs | None = None


def get_database_configs() -> DatabaseConfigs:
    from katti.KattiUtils.Configs.ConfigurationClass import DatabaseConfigs
    global CFG
    if not CFG:
        CFG = DatabaseConfigs.get_config()
    return CFG


def connect_to_database(user='katti', uri=None):
    if uri:
        establish_db_connection(uri)
    else:
        establish_db_connection(get_database_configs().get_mongodb_uri_for_user(user))


def establish_db_connection(mongodb_uri):
        connect(host=mongodb_uri, alias='Katti', db='Katti')


def disconnect_to_database():
    try:
        disconnect(alias='Katti')
    except:
        pass


@contextmanager
def context_manager_db():
    connect_to_database()
    yield
    disconnect_to_database()