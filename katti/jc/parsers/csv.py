"""jc - JSON Convert `csv` file parser

The `csv` parser will attempt to automatically detect the delimiter
character. If the delimiter cannot be detected it will default to comma.
The first row of the file must be a header row.

Usage (cli):

    $ cat file.csv | jc --csv

Usage (module):

    import katti.jc
    result = jc.parse('csv', csv_output)

Schema:

CSV file converted to a Dictionary:
https://docs.python.org/3/library/csv.html

    [
      {
        "column_name1":     string,
        "column_name2":     string
      }
    ]

Examples:

    $ cat homes.csv
    "Sell", "List", "Living", "Rooms", "Beds", "Baths", "Age", "Acres"...
    142, 160, 28, 10, 5, 3,  60, 0.28,  3167
    175, 180, 18,  8, 4, 1,  12, 0.43,  4033
    129, 132, 13,  6, 3, 1,  41, 0.33,  1471
    ...

    $ cat homes.csv | jc --csv -p
    [
      {
        "Sell": "142",
        "List": "160",
        "Living": "28",
        "Rooms": "10",
        "Beds": "5",
        "Baths": "3",
        "Age": "60",
        "Acres": "0.28",
        "Taxes": "3167"
      },
      {
        "Sell": "175",
        "List": "180",
        "Living": "18",
        "Rooms": "8",
        "Beds": "4",
        "Baths": "1",
        "Age": "12",
        "Acres": "0.43",
        "Taxes": "4033"
      },
      {
        "Sell": "129",
        "List": "132",
        "Living": "13",
        "Rooms": "6",
        "Beds": "3",
        "Baths": "1",
        "Age": "41",
        "Acres": "0.33",
        "Taxes": "1471"
      },
      ...
    ]
"""
from typing import List, Union, Type
from katti.jc.jc_types import JSONDictType
import katti.jc.utils
import csv


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.5'
    description = 'CSV file parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    details = 'Using the python standard csv library'
    compatible = ['linux', 'darwin', 'cygwin', 'win32', 'aix', 'freebsd']
    tags = ['standard', 'file', 'string']


__version__ = info.version


def _process(proc_data: List[JSONDictType]) -> List[JSONDictType]:
    """
    Final processing to conform to the schema.

    Parameters:

        proc_data:   (List of Dictionaries) raw structured data to process

    Returns:

        List of Dictionaries. Each Dictionary represents a row in the csv
        file.
    """

    # No further processing
    return proc_data


def parse(
    data: Union[str, bytes],
    raw: bool = False,
    quiet: bool = False
) -> List[JSONDictType]:
    """
    Main text parsing function

    Parameters:

        data:        (string)  text data to parse
        raw:         (boolean) unprocessed output if True
        quiet:       (boolean) suppress warning messages if True

    Returns:

        List of Dictionaries. Raw or processed structured data.
    """
    jc.utils.compatibility(__name__, info.compatible, quiet)
    jc.utils.input_type_check(data)

    # remove BOM bytes, if present
    if isinstance(data, str):
        data = data.encode('utf-8')

    data = data.decode('utf-8-sig')

    raw_output = []
    cleandata = data.splitlines()

    # Clear any blank lines
    cleandata = list(filter(None, cleandata))

    if jc.utils.has_data(data):

        dialect: Union[str, Type[csv.Dialect]]  = 'excel'  # default in csv module
        try:
            dialect = csv.Sniffer().sniff(data[:1024])
            if '""' in data:
                dialect.doublequote = True
        except Exception:
            pass

        reader = csv.DictReader(cleandata, dialect=dialect)

        for row in reader:
            raw_output.append(row)

    return raw_output if raw else _process(raw_output)
