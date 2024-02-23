"""jc - JSON Convert `dmidecode` command output parser

Usage (cli):

    $ dmidecode | jc --dmidecode

or

    $ jc dmidecode

Usage (module):

    import katti.jc
    result = jc.parse('dmidecode', dmidecode_command_output)

Schema:

    [
      {
        "handle":                      string,
        "type":                        integer,
        "bytes":                       integer,
        "description":                 string,
        "values": {                                 # null if empty
          "lowercase_no_spaces_keys":  string,
          "multiline_key_values": [
                                       string,
          ]
        }
      }
    ]

Examples:

    # dmidecode | jc --dmidecode -p
    [
      {
        "handle": "0x0000",
        "type": 0,
        "bytes": 24,
        "description": "BIOS Information",
        "values": {
          "vendor": "Phoenix Technologies LTD",
          "version": "6.00",
          "release_date": "04/13/2018",
          "address": "0xEA490",
          "runtime_size": "88944 bytes",
          "rom_size": "64 kB",
          "characteristics": [
            "ISA is supported",
            "PCI is supported",
            "PC Card (PCMCIA) is supported",
            "PNP is supported",
            "APM is supported",
            "BIOS is upgradeable",
            "BIOS shadowing is allowed",
            "ESCD support is available",
            "Boot from CD is supported",
            "Selectable boot is supported",
            "EDD is supported",
            "Print screen service is supported (int 5h)",
            "8042 keyboard services are supported (int 9h)",
            "Serial services are supported (int 14h)",
            "Printer services are supported (int 17h)",
            "CGA/mono video services are supported (int 10h)",
            "ACPI is supported",
            "Smart battery is supported",
            "BIOS boot specification is supported",
            "Function key-initiated network boot is supported",
            "Targeted content distribution is supported"
          ],
          "bios_revision": "4.6",
          "firmware_revision": "0.0"
        }
      },
      ...
    ]

    # dmidecode | jc --dmidecode -p -r
    [
      {
        "handle": "0x0000",
        "type": "0",
        "bytes": "24",
        "description": "BIOS Information",
        "values": {
          "vendor": "Phoenix Technologies LTD",
          "version": "6.00",
          "release_date": "04/13/2018",
          "address": "0xEA490",
          "runtime_size": "88944 bytes",
          "rom_size": "64 kB",
          "characteristics": [
            "ISA is supported",
            "PCI is supported",
            "PC Card (PCMCIA) is supported",
            "PNP is supported",
            "APM is supported",
            "BIOS is upgradeable",
            "BIOS shadowing is allowed",
            "ESCD support is available",
            "Boot from CD is supported",
            "Selectable boot is supported",
            "EDD is supported",
            "Print screen service is supported (int 5h)",
            "8042 keyboard services are supported (int 9h)",
            "Serial services are supported (int 14h)",
            "Printer services are supported (int 17h)",
            "CGA/mono video services are supported (int 10h)",
            "ACPI is supported",
            "Smart battery is supported",
            "BIOS boot specification is supported",
            "Function key-initiated network boot is supported",
            "Targeted content distribution is supported"
          ],
          "bios_revision": "4.6",
          "firmware_revision": "0.0"
        }
      },
      ...
    ]
"""
import katti.jc.utils


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.5'
    description = '`dmidecode` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux']
    magic_commands = ['dmidecode']
    tags = ['command']


__version__ = info.version


def _process(proc_data):
    """
    Final processing to conform to the schema.

    Parameters:

        proc_data:   (List of Dictionaries) raw structured data to process

    Returns:

        List of Dictionaries. Structured data to conform to the schema.
    """
    int_list = {'type', 'bytes'}

    for entry in proc_data:
        for key in entry:
            if key in int_list:
                entry[key] = jc.utils.convert_to_int(entry[key])

        if not entry['values']:
            entry['values'] = None

    return proc_data


def parse(data, raw=False, quiet=False):
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

    item_header = False
    item_values = False
    value_list = False

    item = None
    header = None
    key = None
    val = None
    attribute = None
    values = None
    key_data = None

    raw_output = []

    if jc.utils.has_data(data):

        data = data.splitlines()

        # remove header rows
        for row in data.copy():
            if row:
                data.pop(0)
            else:
                break

        # main parsing loop
        for line in data:
            # new item
            if not line:
                item_header = True
                item_values = False
                value_list = False

                if item:
                    if values:
                        item['values'][attribute] = values
                    if key_data:
                        item['values'][f'{key}_data'] = key_data
                    raw_output.append(item)

                item = {}
                header = None
                key = None
                val = None
                attribute = None
                values = []
                key_data = []
                continue

            # header
            if line.startswith('Handle ') and line.endswith('bytes'):

                # Handle 0x0000, DMI type 0, 24 bytes
                header = line.replace(',', ' ').split()
                item = {
                    'handle': header[1],
                    'type': header[4],
                    'bytes': header[5]
                }
                continue

            # description
            if item_header:
                item_header = False
                item_values = True
                value_list = False

                item['description'] = line
                item['values'] = {}
                continue

            # new item if multiple descriptions in handle
            if not item_header and not line.startswith('\t'):
                item_header = False
                item_values = True
                value_list = False

                if item:
                    if values:
                        item['values'][attribute] = values
                    if key_data:
                        item['values'][f'{key}_data'] = key_data
                    raw_output.append(item)

                item = {
                    'handle': header[1],
                    'type': header[4],
                    'bytes': header[5],
                    'description': line,
                    'values': {}
                }

                key = None
                val = None
                attribute = None
                values = []
                key_data = []
                continue

            # keys and values
            if item_values \
               and len(line.split(':', maxsplit=1)) == 2 \
               and line.startswith('\t') \
               and not line.startswith('\t\t') \
               and not line.strip().endswith(':'):
                item_header = False
                item_values = True
                value_list = False

                if values:
                    item['values'][attribute] = values
                    values = []
                if key_data:
                    item['values'][f'{key}_data'] = key_data
                    key_data = []

                key = line.split(':', maxsplit=1)[0].strip().lower().replace(' ', '_')
                val = line.split(':', maxsplit=1)[1].strip()
                item['values'].update({key: val})
                continue

            # multi-line key
            if item_values \
               and line.startswith('\t') \
               and not line.startswith('\t\t') \
               and line.strip().endswith(':'):
                item_header = False
                item_values = True
                value_list = True

                if values:
                    item['values'][attribute] = values
                    values = []
                if key_data:
                    item['values'][f'{key}_data'] = key_data
                    key_data = []

                attribute = line[:-1].strip().lower().replace(' ', '_')
                values = []
                continue

            # multi-line values
            if value_list \
               and line.startswith('\t\t'):
                values.append(line.strip())
                continue

            # data for hybrid multi-line objects
            if item_values \
               and not value_list \
               and line.startswith('\t\t'):
                if f'{key}_data' not in item['values']:
                    item['values'][f'{key}_data'] = []
                key_data.append(line.strip())
                continue

        if item:
            raw_output.append(item)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
