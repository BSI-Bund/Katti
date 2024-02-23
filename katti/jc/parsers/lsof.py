"""jc - JSON Convert `lsof` command output parser

Usage (cli):

    $ lsof | jc --lsof

or

    $ jc lsof

Usage (module):

    import katti.jc
    result = jc.parse('lsof', lsof_command_output)

Schema:

    [
      {
        "command":    string,
        "pid":        integer,
        "tid":        integer,
        "user":       string,
        "fd":         string,
        "type":       string,
        "device":     string,
        "size_off":   integer,
        "node":       integer,
        "name":       string
      }
    ]

Examples:

    $ sudo lsof | jc --lsof -p
    [
      {
        "command": "systemd",
        "pid": 1,
        "tid": null,
        "user": "root",
        "fd": "cwd",
        "type": "DIR",
        "device": "253,0",
        "size_off": 224,
        "node": 64,
        "name": "/"
      },
      {
        "command": "systemd",
        "pid": 1,
        "tid": null,
        "user": "root",
        "fd": "rtd",
        "type": "DIR",
        "device": "253,0",
        "size_off": 224,
        "node": 64,
        "name": "/"
      },
      {
        "command": "systemd",
        "pid": 1,
        "tid": null,
        "user": "root",
        "fd": "txt",
        "type": "REG",
        "device": "253,0",
        "size_off": 1624520,
        "node": 50360451,
        "name": "/usr/lib/systemd/systemd"
      },
      ...
    ]

    $ sudo lsof | jc --lsof -p -r
    [
      {
        "command": "systemd",
        "pid": "1",
        "tid": null,
        "user": "root",
        "fd": "cwd",
        "type": "DIR",
        "device": "8,2",
        "size_off": "4096",
        "node": "2",
        "name": "/"
      },
      {
        "command": "systemd",
        "pid": "1",
        "tid": null,
        "user": "root",
        "fd": "rtd",
        "type": "DIR",
        "device": "8,2",
        "size_off": "4096",
        "node": "2",
        "name": "/"
      },
      {
        "command": "systemd",
        "pid": "1",
        "tid": null,
        "user": "root",
        "fd": "txt",
        "type": "REG",
        "device": "8,2",
        "size_off": "1595792",
        "node": "668802",
        "name": "/lib/systemd/systemd"
      },
      ...
    ]
"""
import katti.jc.utils
import katti.jc.parsers.universal


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.6'
    description = '`lsof` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux', 'darwin', 'aix', 'freebsd']
    magic_commands = ['lsof']
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
    int_list = {'pid', 'tid', 'size_off', 'node'}

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

        cleandata[0] = cleandata[0].lower()
        cleandata[0] = cleandata[0].replace('/', '_')

        raw_output = jc.parsers.universal.sparse_table_parse(cleandata)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
