# ICSNPP-DNP3

Industrial Control Systems Network Protocol Parsers (ICSNPP) - DNP3.

## Overview

ICSNPP-DNP3 is a Zeek package that extends the logging capabilities of Zeek's default DNP3 protocol parser.

Zeek's default DNP3 parser logs DNP3 traffic to dnp3.log. This log file remains unchanged. This package extends DNP3 logging capability by adding two new DNP3 log files:
* dnp3_control.log
* dnp3_objects.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-dnp3
```

If ZKG is configured to load packages (see @load packages in quickstart guide), this script will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If users are not using site/local.zeek or another site installation of Zeek and want to run this script on a packet capture, they can add `icsnpp-dnp3` to the command to run this script on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-dnp3.git
zeek -Cr icsnpp-dnp3/tests/traces/dnp3_example.pcap icsnpp-dnp3
```

### Manual Install

To install this script manually, clone this repository and copy the contents of the scripts directory into `${ZEEK_INSTALLATION_DIR}/share/zeek/site/icsnpp-dnp3`.

```bash
git clone https://github.com/cisagov/icsnpp-dnp3.git
zeek_install_dir=$(dirname $(dirname `which zeek`))
cp -r icsnpp-dnp3/scripts/ $zeek_install_dir/share/zeek/site/icsnpp-dnp3
```

If using a site deployment, simply add echo `@load icsnpp-dnp3` to the local.site file.

If users are not using site/local.zeek or another site installation of Zeek, and want to run this package on a packet capture, they can add `icsnpp-dnp3` to the command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-dnp3/tests/traces/dnp3_example.pcap icsnpp-dnp3
```
## Logging Capabilities

### DNP3 Control Log (dnp3_control.log)

#### Overview

This log captures DNP3 Control Relay Output Block and Pattern Control Block data seen in SELECT-OPERATE-RESPONSE commands and logs them to **dnp3_control.log**.

DNP3 Control Relay Output Blocks can be controlled via DNP3 SELECT and OPERATE commands and are among the most common (and most impactful) DNP3 commands.

This log file contains all the relevant data for these SELECT and OPERATE commands (as well as the responses), it shows a more in-depth look at these commands, and it provides a much more detailed look at what operational DNP3 commands are being sent.

#### Fields Captured:

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this connection                                 |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination port (see *Source and Destination Fields*)        |
| block_type            | string    | Control_Relay_Output_Block or Pattern_Control_Block           |
| function_code         | string    | Function code (SELECT, OPERATE, RESPONSE)                     |
| index_number          | count     | Object index number                                           |
| trip_control_code     | string    | Nul, Close, or Trip                                           |
| operation_type        | string    | Nul, Pulse_On, Pulse_Off, Latch_On, Latch_Off                 |
| execute_count         | count     | Number of times to execute                                    |
| on_time               | count     | On time                                                       |
| off_time              | count     | Off time                                                      |
| status_code           | string    | Status code                                                   |

### DNP3 Read Object Log (dnp3_read_objects.log)

#### Overview

This log captures DNP3 Read Object data seen in READ-RESPONSE commands and logs them to **dnp3_objects.log**.

DNP3 READ-RESPONSE commands are very common DNP3 commands and these responses contain a lot of useful information about the DNP3 devices.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this connection                                 |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination port (see *Source and Destination Fields*)        |
| function_code         | string    | Function code (READ or RESPONSE)                              |
| object_type           | string    | DNP3 object type                                              |
| object_count          | count     | Number of objects                                             |
| range_low             | count     | Range (low) of object                                         |
| range_high            | count     | Range (high) of object                                        |

### Source and Destination Fields

#### Overview

Zeek's typical behavior is to focus on and log packets from the originator and not log packets from the responder. However, most ICS protocols contain useful information in the responses, so the ICSNPP parsers log both originator and responses packets. Zeek's default behavior, defined in its `id` struct, is to never switch these originator/responder roles which leads to inconsistencies and inaccuracies when looking at ICS traffic that logs responses.

The default Zeek `id` struct contains the following logged fields:
* id.orig_h (Original Originator/Source Host)
* id.orig_p (Original Originator/Source Port)
* id.resp_h (Original Responder/Destination Host)
* id.resp_p (Original Responder/Destination Port)

Additionally, the `is_orig` field is a boolean field that is set to T (True) when the id_orig fields are the true originators/source and F (False) when the id_resp fields are the true originators/source.

To not break existing platforms that utilize the default `id` struct and `is_orig` field functionality, the ICSNPP team has added four new fields to each log file instead of changing Zeek's default behavior. These four new fields provide the accurate information regarding source and destination IP addresses and ports:
* source_h (True Originator/Source Host)
* source_p (True Originator/Source Port)
* destination_h (True Responder/Destination Host)
* destination_p (True Responder/Destination Port)

The pseudocode below shows the relationship between the `id` struct, `is_orig` field, and the new `source` and `destination` fields.

```
if is_orig == True
    source_h == id.orig_h
    source_p == id.orig_p
    destination_h == id.resp_h
    destination_p == id.resp_p
if is_orig == False
    source_h == id.resp_h
    source_p == id.resp_p
    destination_h == id.orig_h
    destination_p == id.orig_p
```

#### Example

The table below shows an example of these fields in the log files. The first log in the table represents a Modbus request from 192.168.1.10 -> 192.168.1.200 and the second log represents a Modbus reply from 192.168.1.200 -> 192.168.1.10. As shown in the table below, the `id` structure lists both packets as having the same originator and responder, but the `source` and `destination` fields reflect the true source and destination of these packets.

| id.orig_h    | id.orig_p | id.resp_h     | id.resp_p | is_orig | source_h      | source_p | destination_h | destination_p |
| ------------ | --------- |---------------|-----------|---------|---------------|----------|---------------|-------------- |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | T       | 192.168.1.10  | 47785    | 192.168.1.200 | 502           |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | F       | 192.168.1.200 | 502      | 192.168.1.10  | 47785         |

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### License

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE.txt`](./LICENSE.txt)).
