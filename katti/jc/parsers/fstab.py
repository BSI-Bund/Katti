"""jc - JSON Convert `fstab` file parser

Usage (cli):

    $ cat /etc/fstab | jc --fstab

Usage (module):

    import katti.jc
    result = jc.parse('fstab', fstab_command_output)

Schema:

    [
      {
        "fs_spec":      string,
        "fs_file":      string,
        "fs_vfstype":   string,
        "fs_mntops":    string,
        "fs_freq":      integer,
        "fs_passno":    integer
      }
    ]

Examples:

    $ cat /etc/fstab | jc --fstab -p
    [
      {
        "fs_spec": "/dev/mapper/centos-root",
        "fs_file": "/",
        "fs_vfstype": "xfs",
        "fs_mntops": "defaults",
        "fs_freq": 0,
        "fs_passno": 0
      },
      {
        "fs_spec": "UUID=05d927bb-5875-49e3-ada1-7f46cb31c932",
        "fs_file": "/boot",
        "fs_vfstype": "xfs",
        "fs_mntops": "defaults",
        "fs_freq": 0,
        "fs_passno": 0
      },
      {
        "fs_spec": "/dev/mapper/centos-swap",
        "fs_file": "swap",
        "fs_vfstype": "swap",
        "fs_mntops": "defaults",
        "fs_freq": 0,
        "fs_passno": 0
      }
    ]

    $ cat /etc/fstab | jc --fstab -p -r
    [
      {
        "fs_spec": "/dev/mapper/centos-root",
        "fs_file": "/",
        "fs_vfstype": "xfs",
        "fs_mntops": "defaults",
        "fs_freq": "0",
        "fs_passno": "0"
      },
      {
        "fs_spec": "UUID=05d927bb-5875-49e3-ada1-7f46cb31c932",
        "fs_file": "/boot",
        "fs_vfstype": "xfs",
        "fs_mntops": "defaults",
        "fs_freq": "0",
        "fs_passno": "0"
      },
      {
        "fs_spec": "/dev/mapper/centos-swap",
        "fs_file": "swap",
        "fs_vfstype": "swap",
        "fs_mntops": "defaults",
        "fs_freq": "0",
        "fs_passno": "0"
      }
    ]
"""
import katti.jc.utils


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.7'
    description = '`/etc/fstab` file parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    compatible = ['linux', 'freebsd']
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
    int_list = {'fs_freq', 'fs_passno'}

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
    cleandata = data.splitlines()

    # Clear any blank lines
    cleandata = list(filter(None, cleandata))

    if jc.utils.has_data(data):

        for line in cleandata:
            output_line = {}
            # ignore commented lines
            if line.strip().startswith('#'):
                continue

            line_list = line.split(maxsplit=6)
            fs_spec = line_list[0]
            fs_file = line_list[1]
            fs_vfstype = line_list[2]
            fs_mntops = line_list[3]
            fs_freq = line_list[4]
            fs_passno = line_list[5]

            output_line['fs_spec'] = fs_spec
            output_line['fs_file'] = fs_file
            output_line['fs_vfstype'] = fs_vfstype
            output_line['fs_mntops'] = fs_mntops
            output_line['fs_freq'] = fs_freq
            output_line['fs_passno'] = fs_passno

            raw_output.append(output_line)

    if raw:
        return raw_output
    else:
        return _process(raw_output)
