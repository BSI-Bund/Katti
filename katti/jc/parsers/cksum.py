"""jc - JSON Convert `cksum` command output parser

This parser works with the following checksum calculation utilities:
- `sum`
- `cksum`

Usage (cli):

    $ cksum file.txt | jc --cksum

or

    $ jc cksum file.txt

Usage (module):

    import katti.jc
    result = jc.parse('cksum', cksum_command_output)

Schema:

    [
      {
        "filename":     string,
        "checksum":     integer,
        "blocks":       integer
      }
    ]

Examples:

    $ cksum * | jc --cksum -p
    [
      {
        "filename": "__init__.py",
        "checksum": 4294967295,
        "blocks": 0
      },
      {
        "filename": "airport.py",
        "checksum": 2208551092,
        "blocks": 3745
      },
      {
        "filename": "airport_s.py",
        "checksum": 1113817598,
        "blocks": 4572
      },
      ...
    ]
"""
import katti.jc.utils


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.4'
    description = '`cksum` and `sum` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux', 'darwin', 'cygwin', 'aix', 'freebsd']
    magic_commands = ['cksum', 'sum']
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
    int_list = {'checksum', 'blocks'}

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

    if jc.utils.has_data(data):

        for line in filter(None, data.splitlines()):
            item = {
                'filename': line.split(maxsplit=2)[2],
                'checksum': line.split(maxsplit=2)[0],
                'blocks': line.split(maxsplit=2)[1]
            }
            raw_output.append(item)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
