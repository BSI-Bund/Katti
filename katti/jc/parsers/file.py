"""jc - JSON Convert `file` command output parser

Usage (cli):

    $ file * | jc --file

or

    $ jc file *

Usage (module):

    import katti.jc
    result = jc.parse('file', file_command_output)

Schema:

    [
      {
        "filename":   string,
        "type":       string
      }
    ]

Examples:

    $ file * | jc --file -p
    [
      {
        "filename": "Applications",
        "type": "directory"
      },
      {
        "filename": "another file with spaces",
        "type": "empty"
      },
      {
        "filename": "argstest.py",
        "type": "Python script text executable, ASCII text"
      },
      {
        "filename": "blkid-p.out",
        "type": "ASCII text"
      },
      {
        "filename": "blkid-pi.out",
        "type": "ASCII text, with very long lines"
      },
      {
        "filename": "cd_catalog.xml",
        "type": "XML 1.0 document text, ASCII text, with CRLF line ..."
      },
      {
        "filename": "centosserial.sh",
        "type": "Bourne-Again shell script text executable, UTF-8 ..."
      },
      ...
    ]
"""
import katti.jc.utils
import katti.jc.parsers.universal


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.5'
    description = '`file` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux', 'aix', 'freebsd', 'darwin']
    magic_commands = ['file']
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
    # No further processing
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

    warned = False

    if jc.utils.has_data(data):

        for line in filter(None, data.splitlines()):

            # fix case for gzip files where description contains ': ' delimiter
            if 'gzip compressed data, last modified: ' in line:
                linedata = line.split(': ', maxsplit=1)

            # use rsplit to correctly grab filenames containing ': ' delimiter text
            else:
                linedata = line.rsplit(': ', maxsplit=1)

            try:
                filename = linedata[0].strip()
                filetype = linedata[1].strip()

                raw_output.append(
                    {
                        'filename': filename,
                        'type': filetype
                    }
                )
            except IndexError:
                if not warned:
                    jc.utils.warning_message(['Filenames with newline characters detected. Some filenames may be truncated.'])
                    warned = True

    if raw:
        return raw_output
    else:
        return _process(raw_output)
