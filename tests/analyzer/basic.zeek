# @TEST-EXEC: zeek -C -r ${TRACES}/dnp3_example.pcap %PACKAGE
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dnp3.log
# @TEST-EXEC: btest-diff dnp3_control.log
# @TEST-EXEC: btest-diff dnp3_objects.log
#
# @TEST-DOC: Test DNP3 analyzer extennsions with small trace.
