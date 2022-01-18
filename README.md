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

If you have ZKG configured to load packages (see @load packages in quickstart guide), this script will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If you are not using site/local.zeek or another site installation of Zeek and just want to run this script on a packet capture you can add `icsnpp-dnp3` to your command to run this script on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-dnp3.git
zeek -Cr icsnpp-dnp3/examples/dnp3_example.pcap icsnpp-dnp3
```

### Manual Install

To install this script manually, clone this repository and copy the contents of the scripts directory into `${ZEEK_INSTALLATION_DIR}/share/zeek/site/icsnpp-dnp3`.

```bash
git clone https://github.com/cisagov/icsnpp-dnp3.git
zeek_install_dir=$(dirname $(dirname `which zeek`))
cp -r icsnpp-dnp3/scripts/ $zeek_install_dir/share/zeek/site/icsnpp-dnp3
```

If you are using a site deployment, simply add echo `@load icsnpp-dnp3` to your local.site file.

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp-dnp3` to your command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-dnp3/examples/dnp3_example.pcap icsnpp-dnp3
```
## Logging Capabilities

### DNP3 Control Log (dnp3_control.log)

#### Overview

This log captures DNP3 Control Relay Output Block and Pattern Control Block data seen in SELECT-OPERATE-RESPONSE commands and logs them to **dnp3_control.log**.

DNP3 Control Relay Output Blocks can be controlled via DNP3 SELECT and OPERATE commands and are among the most common (and most impactful) DNP3 commands.

This log file contains all the relevant data for these SELECT and OPERATE commands (as well as the responses) and shows a more in-depth look at these commands and provides a much more detailed look as to what operational DNP3 commands are being sent.

#### Fields Captured:

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| block_type            | string    | Control_Relay_Output_Block or Pattern_Control_Block       |
| function_code         | string    | Function Code (SELECT, OPERATE, RESPONSE)                 |
| index_number          | count     | Object Index #                                            |
| trip_control_code     | string    | Nul, Close, or Trip                                       |
| operation_type        | string    | Nul, Pulse_On, Pulse_Off, Latch_On, Latch_Off             |
| execute_count         | count     | Number of times to execute                                |
| on_time               | count     | On Time                                                   |
| off_time              | count     | Off Time                                                  |
| status_code           | string    | Status Code                                               |

### DNP3 Read Object Log (dnp3_read_objects.log)

#### Overview

This log captures DNP3 Read Object data seen in READ-RESPONSE commands and logs them to **dnp3_objects.log**.

DNP3 READ-RESPONSE commands are very common DNP3 commands and these responses contain a lot of useful information about the DNP3 devices.

#### Fields Captured

| Field                 | Type      | Description                                           |
| --------------------- |-----------|-------------------------------------------------------|
| ts                    | time      | Timestamp                                             |
| uid                   | string    | Unique ID for this connection                         |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| function_code         | string    | Function Code (READ or RESPONSE)                      |
| object_type           | string    | DNP3 Object type                                      |
| object_count          | count     | Number of objects                                     |
| range_low             | count     | Range (Low) of object                                 |
| range_high            | count     | Range (High) of object                                |

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
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2020 Battelle Energy Alliance, LLC

Licensed under the 3-Part BSD (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




Licensing
-----
This software is licensed under the terms you may find in the file named "LICENSE" in this directory.

You agree your contributions are submitted under the BSD-3-Clause license. You represent you are authorized to make the contributions and grant the license. If your employer has rights to intellectual property that includes your contributions, you represent that you have received permission to make contributions and grant the required license on behalf of that employer.
