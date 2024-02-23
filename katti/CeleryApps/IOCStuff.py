from typing import Literal

from katti.CeleryApps.KattiApp import katti_app
import iocextract
from katti.KattiUtils.Exceptions.CommonExtensions import UnknownIOCType


@katti_app.task(bind=True)
def get_ioc_out_of_text(self, ioc_type: Literal['url', 'ips', 'email', 'hash', 'tele_nr'], text: str):
    match ioc_type:
        case 'url':
            return {'urls': list(iocextract.extract_urls(text))}
        case 'ips':
            return {'ips': list(iocextract.extract_ips(text))}
        case 'email':
            return {'email': list(iocextract.extract_emails(text))}
        case 'hash':
            return {'md5': list(iocextract.extract_md5_hashes(text)),
                    'sha256': list(iocextract.extract_sha256_hashes(text)),
                    'sha1': list(iocextract.extract_sha1_hashes(text)),
                    'sha512': list(iocextract.extract_sha512_hashes(text))}
        case 'tele_nr':
            return {'tele_nr': list(iocextract.extract_telephone_nums(text))}
        case _:
            raise UnknownIOCType(ioc_type)
