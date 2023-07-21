# @TEST-EXEC: zeek -C -r ${TRACES}/dnp3_example.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff dnp3.log
# @TEST-EXEC: btest-diff dnp3_control.log
# @TEST-EXEC: btest-diff dnp3_objects.log
#
# @TEST-DOC: Test DNP3 analyzer extennsions with small trace.
