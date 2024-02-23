"""jc - JSON Convert `airport -s` command output parser

The `airport` program can be found at `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport`.

Usage (cli):

    $ airport -s | jc --airport-s

or

    $ jc airport -s

Usage (module):

    import katti.jc
    result = jc.parse('airport_s', airport_s_command_output)

Schema:

    [
      {
        "ssid":         string,
        "bssid":        string,
        "rssi":         integer,
        "channel":      string,
        "ht":           boolean,
        "cc":           string,
        "security": [
                        string,
        ]
      }
    ]

Examples:

    $ airport -s | jc --airport-s -p
    [
      {
        "ssid": "DIRECT-4A-HP OfficeJet 3830",
        "bssid": "00:67:eb:2a:a7:3b",
        "rssi": -90,
        "channel": "6",
        "ht": true,
        "cc": "--",
        "security": [
          "WPA2(PSK/AES/AES)"
        ]
      },
      {
        "ssid": "Latitude38",
        "bssid": "c0:ff:d5:d2:7a:f3",
        "rssi": -85,
        "channel": "11",
        "ht": true,
        "cc": "US",
        "security": [
          "WPA2(PSK/AES/AES)"
        ]
      },
      {
        "ssid": "xfinitywifi",
        "bssid": "6e:e3:0e:b8:45:99",
        "rssi": -83,
        "channel": "11",
        "ht": true,
        "cc": "US",
        "security": [
          "NONE"
        ]
      },
      ...
    ]

    $ airport -s | jc --airport -p -r
    [
      {
        "ssid": "DIRECT-F3-HP ENVY 5660 series",
        "bssid": "b0:5a:da:6f:0a:d4",
        "rssi": "-93",
        "channel": "1",
        "ht": "Y",
        "cc": "--",
        "security": "WPA2(PSK/AES/AES)"
      },
      {
        "ssid": "YouAreInfected-5",
        "bssid": "5c:e3:0e:c2:85:da",
        "rssi": "-85",
        "channel": "36",
        "ht": "Y",
        "cc": "US",
        "security": "WPA(PSK/AES,TKIP/TKIP) WPA2(PSK/AES,TKIP/TKIP)"
      },
      {
        "ssid": "YuanFamily",
        "bssid": "5c:e3:0e:b8:5f:9a",
        "rssi": "-84",
        "channel": "11",
        "ht": "Y",
        "cc": "US",
        "security": "WPA(PSK/AES,TKIP/TKIP) WPA2(PSK/AES,TKIP/TKIP)"
      },
      ...
    ]
"""
import katti.jc.utils
import katti.jc.parsers.universal


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.6'
    description = '`airport -s` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['darwin']
    magic_commands = ['airport -s']
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
    for entry in proc_data:

        # convert integers and booleans
        int_list = {'rssi'}
        bool_list = {'ht'}
        for key in entry:
            if key in int_list:
                entry[key] = jc.utils.convert_to_int(entry[key])
            if key in bool_list:
                entry[key] = jc.utils.convert_to_bool(entry[key])

        if 'security' in entry:
            entry['security'] = entry['security'].split()

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
    cleandata = list(filter(None, data.splitlines()))

    if jc.utils.has_data(data):
        # fix headers
        cleandata[0] = cleandata[0].lower()
        cleandata[0] = cleandata[0].replace('-', '_')
        cleandata[0] = cleandata[0].replace('security (auth/unicast/group)', 'security')

        # parse the data
        raw_output = jc.parsers.universal.sparse_table_parse(cleandata)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
