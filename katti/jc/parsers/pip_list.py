"""jc - JSON Convert `pip-list` command output parser

Usage (cli):

    $ pip list | jc --pip-list

or

    $ jc pip list

Usage (module):

    import katti.jc
    result = jc.parse('pip_list', pip_list_command_output)

Schema:

    [
      {
        "package":     string,
        "version":     string,
        "location":    string
      }
    ]

Examples:

    $ pip list | jc --pip-list -p
    [
      {
        "package": "ansible",
        "version": "2.8.5"
      },
      {
        "package": "antlr4-python3-runtime",
        "version": "4.7.2"
      },
      {
        "package": "asn1crypto",
        "version": "0.24.0"
      },
      ...
    ]
"""
import katti.jc.utils
import katti.jc.parsers.universal


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.5'
    description = '`pip list` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux', 'darwin', 'cygwin', 'win32', 'aix', 'freebsd']
    magic_commands = ['pip list', 'pip3 list']
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
    # no further processing
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

        # detect legacy output type
        if ' (' in cleandata[0]:
            for row in cleandata:
                raw_output.append({'package': row.split(' (')[0],
                                   'version': row.split(' (')[1].rstrip(')')})

        # otherwise normal table output
        else:
            # clear separator line
            for i, line in reversed(list(enumerate(cleandata))):
                if '---' in line:
                    cleandata.pop(i)

            cleandata[0] = cleandata[0].lower()

            if cleandata:
                raw_output = jc.parsers.universal.simple_table_parse(cleandata)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
