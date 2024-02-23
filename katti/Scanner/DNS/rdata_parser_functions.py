from bson import SON
from katti.DataBaseStuff.MongoengineDocuments.Common.Link import IP

"""
    List of signature algorithm IDs used by corresponding RRs:
    3 - DSA/SHA-1; 5 - RSA/SHA-1; 6 - DSA/SHA-1/NSEC3; 7 - RSA/SHA-1/NSEC3; 8 - RSA/SHA-256;
    10 - RSA/SHA-512; 12 - GOST R 34.10-2001; 13 - ECDSA/Curve P-256/SHA-256; 14 - ECSDA/Curve P-384/SHA-384
    15 - Ed25519 (EdSDA/Curve25519/SHA-512); 16 - Ed448 (EdSDA/Curve448/SHAKE256)
"""


class RDataParser:
    def do_it(self, rdata, record_type: str) -> dict | SON:
        if not isinstance(rdata, str):
            return {record_type: rdata}

        match record_type.upper():
            case 'A':
                """
                    IPv4 Address record
                    rdata:
                        ipaddr          IPv4 address
                """
                return parse_a_record(rdata)
            case 'AA':
                return parse_mx_record(rdata)
            case 'AAAA':
                """
                    IPv6 Address record
                    rdata:
                        ipaddr          IPv6 address
                """
                return parse_aaaa_record(rdata)
            case 'AFSDB':
                """
                    Andrew File System database record
                    rdata:
                        subtype         subtype
                                            1 - AFS version 3.0 Volume Location Server
                                            2 - authenticated name server holding the cell-root directory node for the named cell
                        target          domain name of the associated AFS database server
                """
                return parse_afsdb_record(rdata)
            case 'AMTRELAY':
                """
                    Automatic Multicast Tunneling relay record
                    rdata:
                        priority        regulates preference between multiple records; lower value is higher priority
                        discover        determines whether this relay may directly receive AMT Requests 
                        type            determines the type of information stored in 'relay'
                                            0 - empty; 1 - IPv4 address; 2 - IPv6 address; 3 - uncompressed wire-encoded domain name
                        relay           depends on type
                """
                return parse_amtrelay_record(rdata)
            case 'APL':
                """
                    Address Prefix List record
                    rdata:
                        apl             address prefix list, each address with the following format:
                                            !afi:cidr, where ! is an optional !, afi is the address family indicator (0 - IPv4, 1 - IPv6),
                                            and cidr is an address prefix in CIDR notation
                """
                return parse_apl_record(rdata)
            case 'ATMA':
                """
                    Asynchronous Transfer Mode Address record
                    rdata:
                        atm_addr       ATM address
                """
                return parse_atma_record(rdata)
            case 'CAA':
                """
                    Certification Authority Authorization record
                    rdata:
                        flag            currently only issuer critical flag is defined, but may be extended in the future
                        tag             string, one of:
                                            issue           authorizes domain holder specified in 'value' to issue certificates for this domain
                                            issuewild       like issue, but wildcard certificates only   
                                            iodef           specifies a method for certificate authorities to report invalid certificate requests
                                                            to the domain name holder using the Incident Object Description Exchange Format
                                            contactemail    contact information
                                            contactphone    contact information
                        value           value depending on 'tag'
                """
                return parse_caa_record(rdata)
            case 'CERT':
                """
                    Certificate record
                    rdata:
                        type            certificate type
                                            0 - reserved; 1 - X.509; 2 - SPKI; 3 - OpenPGP; 4 - URL of X.509 data object; 5 - URL of SPKI certificate
                                            6 - fingerprint and URL of OpenPGP packet; 7 - attribute certificate; 8 - URL of attribute certificate
                                            253 - URI private; 254 - OID private; 255 - reserved
                        key_tag         identificatory number of DNSKEY used to sign
                        algorithms_id   ID of signing algorithm (see signature algorithms at the top)
                        certificate     base-64 encoded certificate or CRL
                """
                return parse_cert_record(rdata)
            case 'CNAME':
                """
                    Canonical Name record
                    rdata:
                        cname           domain alias used to link to an existing A or AAAA record
                """
                return parse_cname_record(rdata)
            case 'DHCID':
                """
                    DHCP Identifier record
                    rdata:
                        hash            SHA-256(<DHCP identifier> <FQDN>)
                """
                return parse_dhcid_record(rdata)
            case 'DLV':
                """
                    DNSSEC Lookaside Validation record
                    rdata:
                        key_tag         identificatory number of DNSKEY
                        algorithms_id   ID of algorithm used to compute the digest (see signature algorithms at the top)
                        digest_type     digest type
                                            1 - SHA-1; 2 - SHA-256; 3 - GOST R 34.11.94; 4 - SHA-384
                        digest          hash value of owner name concatenated with DNSKEY RDATA
                """
                return parse_dlv_record(rdata)
            case 'DNAME':
                """
                    Delegation Name record
                    rdata:
                        dname           domain alias used to link to an existing domain for all records (not just A or AAAA)
                """
                return parse_dname_record(rdata)
            case 'DNSKEY' | 'CDNSKEY' | 'KEY':
                """
                    (Child) DNSSEC Key record; obsolete Key record
                    The formats for all three of them are the same
                    rdata:
                        algorithms_flag Zone Key flag (256) that is always set and Secure Entry Point (257) set for KSK
                        protocol        ID of protocol used
                                            1 - TLS; 2 - email; 3 - DNSSEC; 4 - IPSEC; 255 - all
                        algorithms_id   ID of signing algorithm (see signature algorithms at the top)
                        key             public key
                """
                return parse_dns_key_record(rdata)
            case 'DS' | 'CDS':
                """
                    (Child) DNSSEC Delegation Signer record
                    rdata:
                        key_tag         identificatory number of DNSKEY
                        algorithm       ID of algorithm used to compute the digest (see signature algorithms at the top)
                        digest_type     digest type
                                            1 - SHA-1; 2 - SHA-256; 3 - GOST R 34.11.94; 4 - SHA-384
                        digest          hash value of DNSKEY record
                """
                return parse_ds_record(rdata)
            case 'EUI48' | 'EUI64':
                """
                    Extended Unique Identifier record
                    rdata:
                        eui             MAC address; six (EUI48) / eight (EUI64) two-digit hexadecimal numbers separated by hyphens
                """
                return parse_eui_record(rdata)
            case 'GPOS':
                """
                    Geographical Position record
                    rdata:
                        longitude       float
                        latitude        float
                        altitude        float
                """
                return parse_gpos_record(rdata)
            case 'HINFO':
                """
                    Host Information record
                    rdata:
                        hinfo_0          arbitrary string of up to 40 characters
                        hinfo_1          another arbitrary string of up to 40 characters
                """
                return parse_hinfo_record(rdata)
            case 'HIP':
                """
                    Host Identity Protocol record
                    rdata:
                        algorithms_id   ID of algorithm used to generate the public key
                                            1 - DSA; 2 - RSA; 3 - ECDSA
                        hit             base16-encoded host identity tag
                        key             base64-encoded public key
                        server_list     list of rendezvous server domains in wire-encoded format (may be empty)
                """
                return parse_hip_record(rdata)
            case 'IPSECKEY':
                """
                    IPSEC Key record
                    rdata:
                        priority        regulates preference between multiple records; lower value is higher priority
                        gateway_type    determines the format for the 'gateway' field:
                                            0 - empty; 1 - IPv4 address; 2 - IPv6 address; 3 - uncompressed wire-encoded domain name
                        algorithms_id   ID of algorithm used to generate the public key
                                            1 - DSA; 2 - RSA; 3 - ECDSA
                        gateway         gateway for IPSec tunnel; depends on 'gateway_type'
                        key             base64-encoded public key
                """
                return parse_ipsec_key_record(rdata)
            case 'ISDN':
                """
                    Integrated Service Digital Network telephone number record
                    rdata:
                        isdn            phone number
                        subaddress      optional string of hexadecimal digits
                """
                return parse_isdn_record(rdata)
            case 'KX':
                """
                    Key Exchange record
                    rdata:
                        priority        regulates preference between multiple records; lower value is higher priority
                        target          domain to query for key
                """
                return parse_kx_record(rdata)
            case 'LOC':
                """
                    Location record
                    rdata:
                        d_lat           degrees longitude
                        m_lat           minutes longitude (default to 0)
                        s_lat           seconds longitude (default to 0)
                        lat_dir         N or S
                        d_long          degrees longitude
                        m_long          minutes longitude (default to 0)
                        s_long          seconds longitude (default to 0)
                        long_dir        E or W
                        altitude        altitude in meters
                        size            radius of sphere around target location in meters (default to 1)
                        hp              horizontal precision in meters (default to 10000)
                        vp              vertical precision in meters (default to 10)
                """
                return parse_loc_record(rdata)
            case 'LP':
                """
                    ILNP Locator Pointer record
                    rdata:
                        priority        regulates preference between multiple records; lower value is higher priority
                        target          domain to be queried for L32 or L64 records
                """
                return parse_lp_record(rdata)
            case 'MB':
                """
                    Mailbox record
                    rdata:
                        mailbox         domain name of mailbox
                """
                return parse_mb_record(rdata)
            case 'MX':
                """
                    Mail Exchange record
                    rdata:
                        priority        regulates preference between multiple records; lower value is higher priority
                        mail_host       e-mail server to be used
                """
                return parse_mx_record(rdata)
            case 'NAPTR':
                """
                    Naming Authority Pointer record
                    rdata:
                        order           regulates order in which records must be processed; lower value is higher priority
                        priority        regulates priority in which records with equal order values must be processed; lower value is higher priority
                        flags           arbitrary alphanumeric string to set flags for target application; may be empty
                        services        arbitrary alphanumeric string specifying service parameters
                        regex           regular expression to modify client's domain name and generate the next one
                        replacement     next domain name to query for depending on 'flags'
                """
                return parse_naptr_record(rdata)
            case 'NID':
                """
                    Node Identifier record
                    rdata:
                        priority        regulates preference between multiple records; lower value is higher priority
                        node_id         64-bit ILNP node identifier
                """
                return parse_nid_record(rdata)
            case 'NS':
                """
                    Name Server record
                    rdata:
                        target          host name of the authoritative name server
                                        if multiple records exist, see SOA record for master name server
                """
                return parse_ns_record(rdata)
            case 'PTR':
                """
                    Pointer record
                    rdata:
                        target          host name associated with the queried IP address
                """
                return parse_ptr_record(rdata)
            case 'RP':
                """
                    Responsible Person record
                    rdata:
                        mailbox_dname   domain name of mailbox contact
                        txt_dname       domain name with additional information in its TXT record
                """
                return parse_rp_record(rdata)
            case 'RRSIG':
                """
                    Resource Record Digital Signature record
                    rdata:
                        type            type of resource record covered by this RRSIG record
                        algorithms_id   ID of signature algorithm used (see signature algorithms at the top)
                        labels          number of labels in the owner name of the signed records
                        ttl_orig        TTL of signature at the time of signing
                        expiration      UNIX timestamp denoting expiration time of this signature
                        inception       UNIX timestamp denoting inception time of this signature
                        key_tag         identificatory number of KEY used to sign
                        signer          name of zone holding corresponding DNSKEY
                        signature       base64-encoded signature
                """
                return parse_rrsig_record(rdata)
            case 'RT':
                """
                    Route Through record
                    rdata:
                        priority        regulates preference between multiple records; lower value is higher priority
                        intermediate    domain name of intermediate host to be used to route through when talking to the owner
                """
                return parse_rt_record(rdata)
            case 'SIG':
                """
                    Signature record
                    rdata:
                        type            type of resource record covered by this SIG record
                        algorithms_id   ID of signature algorithm used
                                            1 - MD5; 2 - Diffie-Hellman; 3 - DSA
                        labels          number of labels in the owner name of the signed records
                        ttl_orig        TTL of signature at the time of signing
                        expiration      UNIX timestamp denoting expiration time of this signature
                        inception       UNIX timestamp denoting inception time of this signature
                        key_tag         identificatory number of DNSKEY used to sign
                        signer          name of zone holding corresponding DNSKEY
                        signature       base64-encoded signature
                """
                return parse_sig_record(rdata)
            case 'SOA':
                """
                    Start of Authority record
                    rdata:
                        mname           primary master name server for this authority zone
                        rname           e-mail address of zone administrator in zone file format
                        serial          serial number for this zone
                        refresh         time (s) after which secondary name servers should query the master for the SOA record, to detect zone changes
                        retry           time (s) after which secondary name servers should retry to request the serial number from the master if the master does not respond
                                        retry < refresh
                        expire          time (s) after which secondary name servers should stop answering request for this zone if the master does not respond
                                        expire > retry + refresh
                """
                return parse_soa_record(rdata)
            case 'SPF':
                """
                    Sender Policy Framework record
                    rdata:
                       spf_text         policy for queried domain
                """
                return parse_spf_record(rdata)
            case 'SRV':
                """
                    Service record
                    rdata:
                       priority         regulates preference between multiple records; lower value is higher preference
                       weight           relative weight for records with same priority; higher value is higher preference
                       port             TCP/UDP port on which the service is listening
                       target           canonical host name of the service provider
                """
                return parse_srv_record(rdata)
            case 'SSHFP':
                """
                    SSH Fingerprint record
                    rdata:
                        algorithms_id   ID of fingerprinting algorithm used
                                            0 - reserved; 1 - RSA; 2 - DSA; 3 - ECDSA; 4 - Ed25519
                                            6 - Ed448
                        fprint_type     ID of fingerprint type
                                            0 - reserved; 1 - SHA-1; 2 - SHA-256
                        fprint          SSH fingerprint
                """
                return parse_sshfp_record(rdata)
            case 'TKEY':
                """
                    Transaction Signature record
                    rdata:
                       algorithm        name of the signature algorithm
                       inception        UNIX timestamp denoting inception time of this signature
                       expiration       UNIX timestamp denoting expiration time of this signature
                       mode             general scheme to use for key agreement or the purpose of the TKEY DNS message
                                            0 - reserved; 1 - server assignment; 2 - Diffie-Hellman; 3 - GSS-API; 4 - resolver assignment
                                            5 - key deletion; 65535 - reserved
                       error            error code
                       key_size         length of key
                       key              depends on 'mode'
                       other_size       length of other_data; if 0, there is no other data
                       other_data       arbitrary data
                """
                return parse_tkey_record(rdata)
            case 'TLSA':
                """
                    TLSA record
                    rdata:
                       usage            certificate constraints
                                            0 - PKIX-TA; 1 - PKIX-EE; 2 - DANE-TA; 3 - DANE-EE
                       selector         use full certificate (0) or just public key (1) for matching
                       matching_type    match exactly (0), SHA-256 (1) or SHA-512 (2)
                       hash             hash used for matching, or raw data if 'matching_type' = 0
                """
                return parse_tlsa_record(rdata)
            case 'TSIG':
                """
                    Transaction Signature record
                    rdata:
                       algorithm        name of the signature algorithm
                       time_signed      UNIX timestamp
                       fudge            seconds of error permitted in the above timestamp
                       mac_size         length of the MAC in bytes
                       mac              Message Authentication Code
                       orig_id          original message ID
                       error            error code
                       other_size       length of other_data; if 0, there is no other data
                       other_data       arbitrary data
                """
                return parse_tsig_record(rdata)
            case 'TXT':
                """
                    Text record
                    rdata:
                       text              arbitrary text string to supply additional information
                                        overloaded for a large number of things
                """
                return parse_txt_record(rdata)
            case 'URI':
                """
                    Uniform Resource Identifier record
                    rdata:
                       priority         regulates preference between multiple records; lower value is higher preference
                       weight           relative weight for records with same priority; higher value is higher preference
                       uri              URI
                """
                return parse_uri_record(rdata)
            case _:
                return {'rdata': rdata}


def parse_soa_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'mname': data_split[0],
            'rname': data_split[1],
            'serial': int(data_split[2]),
            'update': int(data_split[3]),
            'retry': int(data_split[4]),
            'expire': int(data_split[5])}


def parse_a_record(rdata: str) -> dict:
    x = IP.build_from_ip_str(rdata).to_mongo().to_dict()
    del x['_cls']
    return x


def parse_aaaa_record(rdata: str) -> dict:
    x = IP.build_from_ip_str(rdata).to_mongo().to_dict()
    del x['_cls']
    return x


def parse_ns_record(rdata: str) -> dict:
    return {'target': rdata}


def parse_dns_key_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'algorithms_flag': int(data_split[0]),
            'protocol': int(data_split[1]),
            'algorithms_id': int(data_split[2]),
            'key': data_split[3]}


def parse_txt_record(rdata: str) -> dict:
    return {'text': rdata.replace('"', '')}


def parse_ds_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'key_tag': int(data_split[0]),
            'algorithm': int(data_split[1]),
            'digest_type': int(data_split[2]),
            'digest': data_split[3]}


def parse_mx_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'priority': int(data_split[0]),
            'mail_host': data_split[1]}


def parse_caa_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'flag': data_split[0],
            'tag': data_split[1],
            'value': data_split[2]}


def parse_cname_record(rdata: str) -> dict:
    return {'cname': rdata}


def parse_ptr_record(rdata: str) -> dict:
    return {'target': rdata}


def parse_srv_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'priority': int(data_split[0]),
            'weight': int(data_split[1]),
            'port': data_split[2],
            'target': data_split[3]}


def parse_tlsa_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'usage': data_split[0],
            'selector': bool(data_split[1]),
            'matching_type': data_split[2],
            'hash': data_split[3]}


def parse_tsig_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    dic = {'algorithm': data_split[0],
           'time_signed': int(data_split[1]),
           'fudge': int(data_split[2]),
           'mac_size': int(data_split[3]),
           'mac': data_split[4],
           'orig_id': int(data_split[5]),
           'error': data_split[6],
           'other_size': int(data_split[7]),
           'other_data': ''}

    if dic['other_size'] > 0:
        dic['other_data'] = data_split[8]

    return dic


def parse_rrsig_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'type': data_split[0],
            'algorithms_id': int(data_split[1]),
            'labels': int(data_split[2]),
            'ttl_orig': int(data_split[3]),
            'expiration': int(data_split[4]),
            'inception': int(data_split[5]),
            'key_tag': int(data_split[6]),
            'signer': data_split[7],
            'signature': data_split[8]}


def parse_sshfp_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'algorithms_id': int(data_split[0]),
            'fprint_type': int(data_split[1]),
            'fprint': data_split[2]}


def parse_rt_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'priority': int(data_split[0]),
            'intermediate': data_split[1]}


def parse_uri_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'priority': int(data_split[0]),
            'weight': int(data_split[1]),
            'uri': data_split[2].replace('"', '')}


def parse_afsdb_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'subtype': int(data_split[0]),
            'target': data_split[1]}


def parse_amtrelay_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    dic = {'priority': int(data_split[0]),
           'discover': bool(data_split[1]),
           'type': int(data_split[2]),
           'relay': ''}

    if dic['type'] > 0:
        dic['relay'] = data_split[3]

    return dic


def parse_apl_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'apl': data_split}


def parse_atma_record(rdata: str) -> dict:
    return {'atm_addr': rdata}


def parse_cert_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'type': data_split[0],
            'key_tag': int(data_split[1]),
            'algorithms_id': int(data_split[2]),
            'certificate': data_split[3]}


def parse_dhcid_record(rdata: str) -> dict:
    return {'hash': rdata}


def parse_dlv_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'key_tag': int(data_split[0]),
            'algorithms_id': int(data_split[1]),
            'digest_type': int(data_split[2]),
            'digest': data_split[3]}


def parse_dname_record(rdata: str) -> dict:
    return {'dname': rdata}


def parse_eui_record(rdata: str) -> dict:
    return {'eui': rdata}


def parse_gpos_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'longitude': float(data_split[0].replace('"', '')),
            'latitude': float(data_split[1].replace('"', '')),
            'altitude': float(data_split[2].replace('"', ''))}


def parse_hinfo_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'hinfo_0': data_split[0].replace('"', ''),
            'hinfo_1': data_split[1].replace('"', '')}


def parse_hip_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    dic = {'algorithms_id': int(data_split[0]),
           'hit': data_split[1],
           'key': data_split[2],
           'server_list': []}

    if len(data_split) > 3:
        dic['server_list'] = data_split[3::]

    return dic


def parse_ipsec_key_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    dic = {'priority': int(data_split[0]),
           'gateway_type': int(data_split[1]),
           'algorithms_id': int(data_split[2]),
           'gateway': '',
           'key': data_split[3]}

    if dic['gateway_type'] > 0:
        dic['gateway'] = data_split[3]
        dic['key'] = data_split[4]

    return dic


def parse_isdn_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    dic = {'isdn': data_split[0],
           'subaddress': ''
           }

    if len(data_split) >= 2:
        dic['subaddress'] = data_split[1]
    return dic


def parse_loc_record(rdata: str) -> dict:
    data_split = rdata.split(' ')

    # initialized to default values as per RFC1876
    dic = {'d_lat': int(data_split[0]),
           'm_lat': 0,
           's_lat': 0,
           'lat_dir': 'N',
           'd_long': 0,
           'm_long': 0,
           's_long': 0,
           'long_dir': 'E',
           'altitude': 0,
           'size': 1,
           'hp': 10000,
           'vp': 10}

    lat_keys = ['d_lat', 'm_lat', 's_lat']
    long_keys = ['d_long', 'm_long', 's_long']

    # determine latitude and longitude formats
    lat_size = 1
    long_size = 1
    for i in range(1, 4):
        if data_split[i] == 'N' or data_split[i] == 'S':
            lat_size = i
            break

    for i in range(lat_size + 2, lat_size + 5):
        if data_split[i] == 'E' or data_split[i] == 'W':
            long_size = i
            break

    # set latitude and longitude
    for i in range(0, 3):
        try:
            dic[lat_keys[i]] = int(data_split[i])
            dic[long_keys[i]] = int(data_split[i + lat_size + 1])
        except (IndexError, ValueError):
            pass
    dic['lat_dir'] = data_split[lat_size]
    dic['long_dir'] = data_split[long_size]
    dic['altitude'] = float(data_split[long_size + 1].replace('m', ''))

    # optional values
    try:
        dic['size'] = float(data_split[long_size + 2].replace('m', ''))
        dic['hp'] = float(data_split[long_size + 3].replace('m', ''))
        dic['vp'] = float(data_split[long_size + 4].replace('m', ''))
    except IndexError:
        pass

    return dic


def parse_lp_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'priority': int(data_split[0]),
            'target': data_split[1]}


def parse_kx_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'priority': int(data_split[0]),
            'target': data_split[1]}


def parse_mb_record(rdata: str) -> dict:
    return {'mailbox': rdata}


def parse_naptr_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    dic = {'order': int(data_split[0]),
           'priority': int(data_split[1]),
           'flags': '',
           'services': data_split[2].replace('"', ''),
           'regex': data_split[3].replace('"', ''),
           'replacement': data_split[4]}

    if len(data_split) > 5:
        dic['flags'] = data_split[2].replace('"', '')
        dic['services'] = data_split[3].replace('"', '')
        dic['regex'] = data_split[4].replace('"', '')
        dic['replacement'] = data_split[5]

    return dic


def parse_nid_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'priority': int(data_split[0]),
            'node_id': data_split[1]}


def parse_rp_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'mailbox_dname': data_split[0],
            'txt_dname': data_split[1]}


def parse_sig_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    return {'type': data_split[0],
            'algorithms_id': int(data_split[1]),
            'labels': int(data_split[2]),
            'ttl_orig': int(data_split[3]),
            'expiration': int(data_split[4]),
            'inception': int(data_split[5]),
            'key_tag': int(data_split[6]),
            'signer': data_split[7],
            'signature': data_split[8]}


def parse_spf_record(rdata: str) -> dict:
    return {'spf_text': rdata.replace('"', '')}


def parse_tkey_record(rdata: str) -> dict:
    data_split = rdata.split(' ')
    dic = {'algorithm': data_split[0],
           'inception': int(data_split[1]),
           'expiration': int(data_split[2]),
           'mode': int(data_split[3]),
           'error': data_split[4],
           'key_size': int(data_split[5]),
           'key': data_split[6],
           'other_size': int(data_split[7]),
           'other_data': ''}

    if dic['other_size'] > 0:
        dic['other_data'] = data_split[8]

    return dic
