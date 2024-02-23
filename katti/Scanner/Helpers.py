import signal

from katti.KattiUtils.Exceptions.ScannerExceptions import BackpropagationNotSupported
from katti.Scanner import load_all_scanner_cls, scanner_type_cls_mapping
from katti.Scanner.BaseScanner import BaseScanner


def preexec_function():
    # warm shutdown -> don't kill running dig processes
    signal.signal(signal.SIGABRT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


def get_all_endpoints():
    load_all_scanner_cls()
    all_endpoints = [scanner_cls.get_scanner_type() for cls_name, scanner_cls in BaseScanner.get_registry().items() if
                     scanner_cls.get_scanner_type()]
    try:
        from katti_api import get_api_endpoint_names
        all_endpoints.extend(get_api_endpoint_names())
    except ImportError:
        print('API package is not present.')
    return all_endpoints


def get_backpropagation_results(start_result: dict):
    if not 'backpropagation' in start_result:
        return []
    else:
        scanner_mapping = scanner_type_cls_mapping()
        back_final_results = {}
        for back, result_ids in start_result.get('backpropagation', {}).items():
            scanner_cls = scanner_mapping.get(back)
            if not scanner_cls:
                continue
                #maybe Exception()
            else:
                try:
                    sub_results = [x.get_complete_result() for x in scanner_cls.get_result_class().objects(id__in=result_ids)]
                    for i in sub_results:
                        get_backpropagation_results(i)
                    back_final_results.update({back: sub_results})
                except BackpropagationNotSupported():
                    continue
            start_result['backpropagation'] = back_final_results
       # start_result['backpropagation'] = back_final_results