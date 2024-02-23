"""jc - JSON Convert `/etc/shadow` file parser

Usage (cli):

    $ sudo cat /etc/shadow | jc --shadow

Usage (module):

    import katti.jc
    result = jc.parse('shadow', shadow_file_output)

Schema:

    [
      {
        "username":       string,
        "password":       string,
        "last_changed":   integer,
        "minimum":        integer,
        "maximum":        integer,
        "warn":           integer,
        "inactive":       integer,
        "expire":         integer
      }
    ]

Examples:

    $ sudo cat /etc/shadow | jc --shadow -p
    [
      {
        "username": "root",
        "password": "*",
        "last_changed": 18113,
        "minimum": 0,
        "maximum": 99999,
        "warn": 7,
        "inactive": null,
        "expire": null
      },
      {
        "username": "daemon",
        "password": "*",
        "last_changed": 18113,
        "minimum": 0,
        "maximum": 99999,
        "warn": 7,
        "inactive": null,
        "expire": null
      },
      {
        "username": "bin",
        "password": "*",
        "last_changed": 18113,
        "minimum": 0,
        "maximum": 99999,
        "warn": 7,
        "inactive": null,
        "expire": null
      },
      ...
    ]

    $ sudo cat /etc/shadow | jc --shadow -p -r
    [
      {
        "username": "root",
        "password": "*",
        "last_changed": "18113",
        "minimum": "0",
        "maximum": "99999",
        "warn": "7",
        "inactive": "",
        "expire": ""
      },
      {
        "username": "daemon",
        "password": "*",
        "last_changed": "18113",
        "minimum": "0",
        "maximum": "99999",
        "warn": "7",
        "inactive": "",
        "expire": ""
      },
      {
        "username": "bin",
        "password": "*",
        "last_changed": "18113",
        "minimum": "0",
        "maximum": "99999",
        "warn": "7",
        "inactive": "",
        "expire": ""
      },
      ...
    ]
"""
import katti.jc.utils


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.5'
    description = '`/etc/shadow` file parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux', 'darwin', 'aix', 'freebsd']
    tags = ['file']


__version__ = info.version


def _process(proc_data):
    """
    Final processing to conform to the schema.

    Parameters:

        proc_data:   (List of Dictionaries) raw structured data to process

    Returns:

        List of Dictionaries. Structured data to conform to the schema.
    """
    int_list = {'last_changed', 'minimum', 'maximum', 'warn', 'inactive', 'expire'}

    for entry in proc_data:
        for key in entry:
            if key in int_list:
                entry[key] = jc.utils.convert_to_int(entry[key])

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

    raw_output = []

    # Clear any blank lines
    cleandata = list(filter(None, data.splitlines()))

    if jc.utils.has_data(data):

        for entry in cleandata:
            if entry.startswith('#'):
                continue

            output_line = {}
            fields = entry.split(':')

            output_line['username'] = fields[0]
            output_line['password'] = fields[1]
            output_line['last_changed'] = fields[2]
            output_line['minimum'] = fields[3]
            output_line['maximum'] = fields[4]
            output_line['warn'] = fields[5]
            output_line['inactive'] = fields[6]
            output_line['expire'] = fields[7]

            raw_output.append(output_line)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
