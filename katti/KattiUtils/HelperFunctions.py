import base64
import datetime
import io
import ipaddress
import os.path
import sys
import time
import pydantic.error_wrappers
from pydantic.dataclasses import dataclass
from pydantic import AnyUrl
import dhash
import validators
from PIL import Image
from bson import ObjectId
from validators import ValidationError
from katti.KattiUtils.Configs.ConfigKeys import KATTI_I_AM_HOME_FLAG
from importlib.util import spec_from_file_location, module_from_spec


def split(list_a, chunk_size):
  for i in range(0, len(list_a), chunk_size):
    yield list_a[i:i + chunk_size]


def sleep(how_long, stop_event):
    start = datetime.datetime.now()
    while (datetime.datetime.now() - start <= how_long and how_long > 0) and not stop_event.is_set():
        time.sleep(1)


def is_valid_domain(domain: str):
    if isinstance(validators.domain(domain), ValidationError):
        return False
    return True


def is_ip_addr_valid(ip_addr: str):
    try:
        ip = ipaddress.ip_address(ip_addr)
    except ValueError:
        return False
    else:
        return True


def is_valid_ipv4(ip_v4_str: str):
    try:
        ipaddress.IPv4Address(ip_v4_str)
    except ipaddress.AddressValueError:
        return False
    return True

def is_valid_ip_v4_or_v6(ip: str):
    if is_ip_addr_valid(ip):
        if is_valid_ipv4(ip):
            return 4
        else:
            return 6
    return 0


@dataclass
class TestUrl:
    url: AnyUrl


def is_valid_url(url: str) -> bool:
    try:
        TestUrl(url=url)
    except pydantic.error_wrappers.ValidationError:
        return False
    return True


def convert_micro_timestamp_to_datetime(timestamp: int) -> datetime.datetime | None:
    if not timestamp:
        return None
    try:
        datetim_e = datetime.datetime.fromtimestamp(timestamp / 1000)
    except Exception:
        return None
    else:
        return datetim_e

def get_today_as_datetime():
    return datetime.datetime.combine(datetime.date.today(), datetime.datetime.min.time())


def get_day_datetime(date: datetime):
    return datetime.datetime.combine(date, datetime.datetime.min.time())


def calculate_dhash(raw_pic, pic_id):
    image = Image.open(io.BytesIO(raw_pic))
    return dhash.dhash_row_col(image)


def json_serialiser(objc):
    if isinstance(objc, (bytes, bytearray)):
        return base64.b64encode(objc).decode('utf-8')
    if isinstance(objc, ObjectId):
        return str(objc)
    if isinstance(objc, datetime.datetime):
        return str(objc)
    raise ValueError(f'No encoding handler for data type {type(objc)}')


def import_module_by_path(module_path, module_name):
   spec = spec_from_file_location(module_name, module_path)
   custom_module = module_from_spec(spec)
   sys.modules[module_name] = custom_module
   spec.loader.exec_module(custom_module)

   return custom_module


def i_am_at_home() -> bool:
    return os.path.exists(KATTI_I_AM_HOME_FLAG)