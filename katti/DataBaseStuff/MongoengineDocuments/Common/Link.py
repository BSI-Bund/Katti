import datetime
from urllib.parse import urlsplit, parse_qs
import vt
from mongoengine import EmbeddedDocument, StringField, BooleanField, DictField, DynamicField, \
    IntField, BinaryField, DateTimeField
from katti.cidrize.cidrize import cidrize


class IP(EmbeddedDocument):
    meta = {'allow_inheritance': True}

    ip_str = StringField()
    ip_number = BinaryField()
    version = IntField()
    date = DateTimeField()
    port = IntField()

    @classmethod
    def build_from_ip_str(cls, ip_str: str, date: datetime.datetime=None, port: int = None):
        new = cls(ip_str=ip_str)
        if date:
            new.date = date
        if port:
            new.port = port
        try:
            cidr = cidrize(ip_str)
            cidr_info = cidr[0].key()
            new.version = cidr_info[0]
            new.ip_number = ip_to_bytes(cidr_info[1], cidr_info[0])
        except Exception:
            pass
        return new


class CIDR(EmbeddedDocument):
    error = BooleanField(default=None)
    cidr_str = StringField()
    version = IntField()
    first_ip = BinaryField()
    last_ip = BinaryField()

    @classmethod
    def build_from_cidr(cls, cidr_str=None, ip_start=None, ip_end=None):
        if cidr_str:
            new = cls(cidr_str=cidr_str)
            try:
                cidr = cidrize(cidr_str)
            except Exception:
                new.error = True
                return new
        else:
            try:
                cidr = cidrize(f'{ip_start}-{ip_end}')
                new = cls(cidr_str=str(cidr[0].cidr))
            except Exception:
                return cls(cidr_str=f'{ip_start}-{ip_end}', error=True)
        try:
            cidr_info = cidr[0].key()
            new.version = cidr_info[0]
            new.first_ip = ip_to_bytes(cidr[0].first, cidr_info[0])
            new.last_ip = ip_to_bytes(cidr[0].last, cidr_info[0])
        except Exception:
            pass
        return new


def ip_to_bytes(ip_as_int: int, version: int) -> bytes | None:
    match version:
        case 4:
            return ip_as_int.to_bytes(length=8, byteorder='big', signed=False)
        case 6:
            return ip_as_int.to_bytes(length=16, byteorder='big', signed=False)
    return None


class URL(EmbeddedDocument):
    meta = {'abstract': True}
    url = StringField()
    domain = StringField()
    url_only_with_path = StringField()
    vt_id = StringField()
    query = DictField()
    fragment = DynamicField()

    @classmethod
    def build(cls, url):
        url_parser_obj = urlsplit(url)
        new_url = cls(url=url)
        new_url.url_only_with_path = f'{url_parser_obj.scheme}://{url_parser_obj.netloc}{url_parser_obj.path}'
        new_url.query = parse_qs(url_parser_obj.query) if len(parse_qs(url_parser_obj.query)) > 0 else None
        new_url.vt_id = vt.url_id(new_url.url_only_with_path)
        new_url.domain = url_parser_obj.hostname
        new_url.fragment = url_parser_obj.fragment if not url_parser_obj.fragment == '' else None

        if new_url.query: #$ is reserved in MonogoDB
            x = {}
            for key in new_url.query:
                try:
                    x.update({key.replace('$', '<dollar>'): new_url.query[key]})
                except Exception:
                    pass
            new_url.query = x
        return new_url


class Link(URL):
    type = StringField(choices=['intern', 'extern', 'social_media', 'unrated'], default='unrated')
