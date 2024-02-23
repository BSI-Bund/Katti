import pprint
import sys
import traceback
from inspect import getmembers

SSL_SCANNER_ALLOWED_COMMANDS = ['ssl_2_0_cipher_suites',
                                'ssl_3_0_cipher_suites',
                                'tls_1_0_cipher_suites',
                                'tls_1_1_cipher_suites',
                                'tls_1_2_cipher_suites',
                                'tls_1_3_cipher_suites',
                                'tls_compression',
                                'certificate_info',
                                'tls_1_3_early_data']

from abc import ABCMeta

class ScannerRegistryBase(ABCMeta):

    REGISTRY = {}
    def __new__(cls, name, bases, attrs):
        new_cls = super().__new__(cls, name, bases, attrs)
        cls.REGISTRY[new_cls.__name__] = new_cls
        return new_cls

    @classmethod
    def get_registry(cls):
        return dict(cls.REGISTRY)


def get_scanner_quota_endpoint_names():
    pass


def load_all_scanner_cls():
    import inspect
    import os
    import importlib
    xe = 'katti.Scanner'
    feed_pkg_path = os.path.dirname(inspect.getfile(ScannerRegistryBase))
    for x in os.walk(feed_pkg_path):
        next_file = x[0].split('/')[-1]
        if next_file == '__pycache__':
            continue
        for file in x[2]:
            if '.py' in file:
                try:
                    importlib.import_module(f'{xe}.{next_file}.{file.replace(".py", "")}')
                except (ModuleNotFoundError, ImportError) as e:
                    pass
                    #pprint.pprint(traceback.format_exception(*sys.exc_info()))


def scanner_type_cls_mapping():
    load_all_scanner_cls()
    return {value.get_scanner_type(): value for key, value in ScannerRegistryBase.get_registry().items()}