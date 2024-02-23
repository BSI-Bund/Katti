"""jc - JSON Convert `airport -I` command output parser

The `airport` program can be found at `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport`.

Usage (cli):

    $ airport -I | jc --airport

or

    $ jc airport -I

Usage (module):

    import katti.jc
    result = jc.parse('airport', airport_command_output)

Schema:

    {
      "agrctlrssi":        integer,
      "agrextrssi":        integer,
      "agrctlnoise":       integer,
      "agrextnoise":       integer,
      "state":             string,
      "op_mode":           string,
      "lasttxrate":        integer,
      "maxrate":           integer,
      "lastassocstatus":   integer,
      "802_11_auth":       string,
      "link_auth":         string,
      "bssid":             string,
      "ssid":              string,
      "mcs":               integer,
      "channel":           string
    }

Examples:

    $ airport -I | jc --airport -p
    {
      "agrctlrssi": -66,
      "agrextrssi": 0,
      "agrctlnoise": -90,
      "agrextnoise": 0,
      "state": "running",
      "op_mode": "station",
      "lasttxrate": 195,
      "maxrate": 867,
      "lastassocstatus": 0,
      "802_11_auth": "open",
      "link_auth": "wpa2-psk",
      "bssid": "3c:37:86:15:ad:f9",
      "ssid": "SnazzleDazzle",
      "mcs": 0,
      "channel": "48,80"
    }

    $ airport -I | jc --airport -p -r
    {
      "agrctlrssi": "-66",
      "agrextrssi": "0",
      "agrctlnoise": "-90",
      "agrextnoise": "0",
      "state": "running",
      "op_mode": "station",
      "lasttxrate": "195",
      "maxrate": "867",
      "lastassocstatus": "0",
      "802_11_auth": "open",
      "link_auth": "wpa2-psk",
      "bssid": "3c:37:86:15:ad:f9",
      "ssid": "SnazzleDazzle",
      "mcs": "0",
      "channel": "48,80"
    }
"""
import katti.jc.utils


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.5'
    description = '`airport -I` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['darwin']
    magic_commands = ['airport -I']
    tags = ['command']


__version__ = info.version


def _process(proc_data):
    """
    Final processing to conform to the schema.

    Parameters:

        proc_data:   (Dictionary) raw structured data to process

    Returns:

        Dictionary. Structured data to conform to the schema.
    """
    int_list = {'agrctlrssi', 'agrextrssi', 'agrctlnoise', 'agrextnoise',
                'lasttxrate', 'maxrate', 'lastassocstatus', 'mcs'}

    for key in proc_data:
        if key in int_list:
            proc_data[key] = jc.utils.convert_to_int(proc_data[key])

    return proc_data


def parse(data, raw=False, quiet=False):
    """
    Main text parsing function

    Parameters:

        data:        (string)  text data to parse
        raw:         (boolean) unprocessed output if True
        quiet:       (boolean) suppress warning messages if True

    Returns:

        Dictionary. Raw or processed structured data.
    """
    jc.utils.compatibility(__name__, info.compatible, quiet)
    jc.utils.input_type_check(data)

    raw_output = {}

    if jc.utils.has_data(data):

        for line in filter(None, data.splitlines()):
            linedata = line.split(':', maxsplit=1)
            key = linedata[0].strip().lower().replace(' ', '_').replace('.', '_')
            value = linedata[1].strip()
            raw_output[key] = value

    if raw:
        return raw_output
    else:
        return _process(raw_output)
