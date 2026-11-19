# @TEST-EXEC: zeek -C -r ${TRACES}/dnp3_read.pcap $PACKAGE %INPUT && mv dnp3_point_values.log read.log
# @TEST-EXEC: zeek -C -r ${TRACES}/dnp3_zeek.pcap $PACKAGE %INPUT && mv dnp3_point_values.log events.log
# @TEST-EXEC: zeek -C -r ${TRACES}/dnp3_udp_read.pcap $PACKAGE %INPUT && mv dnp3_point_values.log float.log
# @TEST-EXEC: btest-diff read.log
# @TEST-EXEC: btest-diff events.log
# @TEST-EXEC: btest-diff float.log
#
# @TEST-DOC: Test dnp3_point_values.log: integer analog inputs (range qualifier), analog change events with index prefixes, counters, frozen counters and single-precision floats over UDP.
