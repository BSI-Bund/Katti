"""jc - JSON Convert `/etc/hosts` file parser

Usage (cli):

    $ cat /etc/hosts | jc --hosts

Usage (module):

    import katti.jc
    result = jc.parse('hosts', hosts_file_output)

Schema:

    [
      {
        "ip":           string,
        "hostname": [
                        string
        ]
      }
    ]

Examples:

    $ cat /etc/hosts | jc --hosts -p
    [
      {
        "ip": "127.0.0.1",
        "hostname": [
          "localhost"
        ]
      },
      {
        "ip": "127.0.1.1",
        "hostname": [
          "root-ubuntu"
        ]
      },
      {
        "ip": "::1",
        "hostname": [
          "ip6-localhost",
          "ip6-loopback"
        ]
      },
      {
        "ip": "fe00::0",
        "hostname": [
          "ip6-localnet"
        ]
      },
      {
        "ip": "ff00::0",
        "hostname": [
          "ip6-mcastprefix"
        ]
      },
      {
        "ip": "ff02::1",
        "hostname": [
          "ip6-allnodes"
        ]
      },
      {
        "ip": "ff02::2",
        "hostname": [
          "ip6-allrouters"
        ]
      }
    ]
"""
import katti.jc.utils


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.4'
    description = '`/etc/hosts` file parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux', 'darwin', 'cygwin', 'win32', 'aix', 'freebsd']
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

    # no additional processing needed
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

        for line in cleandata:
            output_line = {}
            # ignore commented lines
            if line.strip().startswith('#'):
                continue

            line_list = line.split(maxsplit=1)
            ip = line_list[0]
            hosts = line_list[1]
            hosts_list = hosts.split()

            comment_found = False
            for i, item in enumerate(hosts_list):
                if '#' in item:
                    comment_found = True
                    comment_item = i
                    break

            if comment_found:
                hosts_list = hosts_list[:comment_item]

            output_line['ip'] = ip
            output_line['hostname'] = hosts_list

            raw_output.append(output_line)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
