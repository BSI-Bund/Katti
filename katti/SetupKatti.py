import secrets
from katti.DataBaseStuff.ConnectDisconnect import context_manager_db
from katti.DataBaseStuff.MongoengineDocuments.UserManagement.TimeLord import TimeLord, API
from katti.KattiUtils.Configs.Paths import KATTI_SCANNER_CONFIG
from katti.KattiUtils.ConfigRead import ReadConfigWithSecrets
from katti.Scanner import load_all_scanner_cls
from katti.Scanner.BaseScanner import BaseScanner, InitScanner_config
from katti.Scanner.Helpers import get_all_endpoints
from katti.KattiUtils.Configs.ConfigHolder import ConfigDatabaseObject

system_user = {'first_name': 'drwho',
                    'last_name': 'drwho',
                    'email': 'drwho@gallifrey.com',
                    'department': 'Gallifrey1'}

def set_up_scanner():
    load_all_scanner_cls()
    scanner_type_cls_mapping = {cls.get_scanner_type(): cls for cls_name, cls in BaseScanner.get_registry().items() if
                                not cls_name == 'BaseScanner'}
    config_reader = ReadConfigWithSecrets()
    for scanner in config_reader.read_config_with_secrets(KATTI_SCANNER_CONFIG)['scanner']:
        print(
            f'Updated scanner: {scanner["name"]} ID: {scanner_type_cls_mapping[scanner["scanner_type"]].add_final_scanner_to_system(InitScanner_config(**scanner)).id}')

def set_up_system_user():
    new_system_user = TimeLord(**system_user)
    new_system_user.ensure_indexes()
    new_system_user.api = API(
        endpoints=[API.Endpoint(endpoint_name=endpoint_name, access=True, daily_rate=0) for endpoint_name in
                   get_all_endpoints()],
        key=str(secrets.token_urlsafe( 30 * 3 // 4)))
    as_son = new_system_user.to_mongo()
    x = TimeLord.objects(first_name=new_system_user.first_name).modify(__raw__={'$set': as_son}, upsert=True,   new=True)
    print(f'System user is ready. The ID is: {x.id}')
    return x.id


def set_up_config_stuff():
    pass


if __name__ == '__main__':

    with context_manager_db():
        id = set_up_system_user()
        print(id)
        ConfigDatabaseObject(system_user_id=id).save()
        set_up_scanner()
