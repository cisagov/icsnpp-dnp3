##! main.zeek (Updated)
##!
##! Binpac DNP3 Protocol Analyzer - Contains the base script-layer functionality for processing events 
##!                                 emitted from the analyzer. (Utilizes Zeek's built-in DNP3 parser)
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

module DNP3_Extended;

export {
    redef enum Log::ID += { LOG_CONTROL, 
                            LOG_OBJECTS,
                            LOG_POINT_VALUES };

    ###############################################################################################
    ################################  Control -> dnp3_control.log  ################################
    ###############################################################################################
    type Control: record {
        ts                      : time      &log;             ##< Timestamp of event
        uid                     : string    &log;             ##< Zeek unique ID for connection
        id                      : conn_id   &log;             ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool      &optional &log;   ##< the message came from the originator/client or the responder/server
        source_h                : addr      &optional &log;   ##< Source IP Address
        source_p                : port      &optional &log;   ##< Source Port
        destination_h           : addr      &optional &log;   ##< Destination IP Address
        destination_p           : port      &optional &log;   ##< Destination Port
        block_type              : string    &optional &log;   ##< Control_Relay_Output_Block or Pattern_Control_Block
        function_code           : string    &optional &log;   ##< Function Code (SELECT, OPERATE, RESPONSE)
        index_number            : count     &optional &log;   ##< Object Index #
        trip_control_code       : string    &optional &log;   ##< Nul, Close, or Trip
        operation_type          : string    &optional &log;   ##< Nul, Pulse_On, Pulse_Off, Latch_On, Latch_Off
        clear_bit               : bool      &optional &log;   ##< Control code clear bit set (T) or unset (F)
        execute_count           : count     &optional &log;   ##< Number of times to execute
        on_time                 : count     &optional &log;   ##< On Time
        off_time                : count     &optional &log;   ##< Off Time
        status_code             : string    &optional &log;   ##< Status Code (see control_block_status_codes)
    };
    global log_control: event(rec: Control);

    ###############################################################################################
    ################################  Objects -> dnp3_objects.log  ################################
    ###############################################################################################
    type Objects: record {
        ts                      : time      &log;             ##< Timestamp of event
        uid                     : string    &log;             ##< Zeek unique ID for connection
        id                      : conn_id   &log;             ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool      &optional &log;   ##< the message came from the originator/client or the responder/server
        source_h                : addr      &optional &log;   ##< Source IP Address
        source_p                : port      &optional &log;   ##< Source Port
        destination_h           : addr      &optional &log;   ##< Destination IP Address
        destination_p           : port      &optional &log;   ##< Destination Port
        function_code           : string    &optional &log;   ##< Function Code (READ or RESPONSE)
        object_type             : string    &optional &log;   ##< Object type (see dnp3_objects)
        object_count            : count     &optional &log;   ##< Number of objects
        range_low               : count     &optional &log;   ##< Range (Low) of object
        range_high              : count     &optional &log;   ##< Range (High) of object
    };
    global log_objects: event(rec: Objects);

    ###############################################################################################
    ##########################  Point Values -> dnp3_point_values.log  ###########################
    ###############################################################################################
    type Point_Values: record {
        ts                      : time      &log;             ##< Timestamp of event
        uid                     : string    &log;             ##< Zeek unique ID for connection
        id                      : conn_id   &log;             ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool      &optional &log;   ##< the message came from the originator/client or the responder/server
        source_h                : addr      &optional &log;   ##< Source IP Address
        source_p                : port      &optional &log;   ##< Source Port
        destination_h           : addr      &optional &log;   ##< Destination IP Address
        destination_p           : port      &optional &log;   ##< Destination Port
        function_code           : string    &optional &log;   ##< Function Code (e.g. RESPONSE, UNSOLICITED_RESPONSE)
        object_type             : string    &optional &log;   ##< Object type (see dnp3_objects)
        point_index             : count     &optional &log;   ##< Point index (from the index prefix or the start of the range)
        flag                    : count     &optional &log;   ##< Flag octet (quality bits) when the variation carries one
        value                   : double    &optional &log;   ##< Point value (integers sign-decoded, floats IEEE-754 decoded)
        point_time              : time      &optional &log;   ##< Time of the value when the variation carries one
    };
    global log_point_values: event(rec: Point_Values);
}

## Qualifier and position of the object header currently being parsed, per direction
type Point_State: record {
    qualifier                   : count;
    range_low                   : count;
    ordinal                     : count &default=0;
    prefix                      : count &default=0;
};

redef record connection += {
    dnp3_control: Control &optional;
    dnp3_objects: Objects &optional;
    dnp3_point_state: table[bool] of Point_State &optional;
};

###################################################################################################
#################  Defines Log Streams for dnp3_control.log and dnp3_objects.log  #################
###################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(DNP3_Extended::LOG_CONTROL, [$columns=Control, 
                                                    $ev=log_control, 
                                                    $path="dnp3_control"]);

    Log::create_stream(DNP3_Extended::LOG_OBJECTS, [$columns=Objects, 
                                                    $ev=log_objects, 
                                                    $path="dnp3_objects"]);

    Log::create_stream(DNP3_Extended::LOG_POINT_VALUES, [$columns=Point_Values,
                                                         $ev=log_point_values,
                                                         $path="dnp3_point_values"]);
}

###################################################################################################
#########################  Saves prefix_value to DNP3 connection object  ##########################
###################################################################################################
event dnp3_object_prefix(c: connection, 
                         is_orig: bool, 
                         prefix_value: count){

    if ( ! c?$dnp3_control )
        c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];
    
    c$dnp3_control$index_number = prefix_value;
}

###################################################################################################
########################  Saves function_code to DNP3 control and objects #########################
###################################################################################################
event dnp3_application_request_header(c: connection, 
                                      is_orig: bool,
                                      application_control: count, 
                                      fc: count) &priority=2{

    c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];
    c$dnp3_control$function_code = function_codes[fc];

    c$dnp3_objects = [$ts=network_time(), $uid=c$uid, $id=c$id];
    c$dnp3_objects$function_code = function_codes[fc];
}

###################################################################################################
########################  Saves function_code to DNP3 control and objects #########################
###################################################################################################
event dnp3_application_response_header(c: connection, 
                                       is_orig: bool, 
                                       application_control: count, 
                                       fc: count, 
                                       iin: count) &priority=2{

    c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];
    c$dnp3_control$function_code = function_codes[fc];

    c$dnp3_objects = [$ts=network_time(), $uid=c$uid, $id=c$id];
    c$dnp3_objects$function_code = function_codes[fc];
}

###################################################################################################
####################  Defines logging of dnp3_crob event -> dnp3_control.log  #####################
###################################################################################################
event dnp3_crob(c: connection, 
                is_orig: bool, 
                control_code: count, 
                count8: count, 
                on_time: count, 
                off_time: count, 
                status_code: count) &priority=-4{

    if ( ! c?$dnp3_control )
        c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];
    
    c$dnp3_control$is_orig  = is_orig;

    if(is_orig)
    {
        c$dnp3_control$source_h = c$id$orig_h;
        c$dnp3_control$source_p = c$id$orig_p;
        c$dnp3_control$destination_h = c$id$resp_h;
        c$dnp3_control$destination_p = c$id$resp_p;
    }else
    {
        c$dnp3_control$source_h = c$id$resp_h;
        c$dnp3_control$source_p = c$id$resp_p;
        c$dnp3_control$destination_h = c$id$orig_h;
        c$dnp3_control$destination_p = c$id$orig_p;
    }

    c$dnp3_control$block_type = "Control Relay Output Block";
    c$dnp3_control$trip_control_code = control_block_trip_code[((control_code & 0xc0)/64)];
    c$dnp3_control$operation_type = control_block_operation_type[(control_code & 0xf)];
    c$dnp3_control$clear_bit = ((control_code & 0x20) >> 5) == 1;
    c$dnp3_control$execute_count = count8;
    c$dnp3_control$on_time = on_time;
    c$dnp3_control$off_time = off_time;

    if (c$dnp3_control$function_code == "RESPONSE") {
        c$dnp3_control$status_code = control_block_status_codes[status_code];    
    } else {
        delete c$dnp3_control$status_code;
    }

    Log::write(LOG_CONTROL, c$dnp3_control);
}

###################################################################################################
#####################  Defines logging of dnp3_pcb event -> dnp3_control.log  #####################
###################################################################################################
event dnp3_pcb(c: connection, 
               is_orig: bool, 
               control_code: count, 
               count8: count, 
               on_time: count, 
               off_time: count, 
               status_code: count) &priority=-4{

    if ( ! c?$dnp3_control )
        c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];
    
    c$dnp3_control$is_orig  = is_orig;

    if(is_orig)
    {
        c$dnp3_control$source_h = c$id$orig_h;
        c$dnp3_control$source_p = c$id$orig_p;
        c$dnp3_control$destination_h = c$id$resp_h;
        c$dnp3_control$destination_p = c$id$resp_p;
    }else
    {
        c$dnp3_control$source_h = c$id$resp_h;
        c$dnp3_control$source_p = c$id$resp_p;
        c$dnp3_control$destination_h = c$id$orig_h;
        c$dnp3_control$destination_p = c$id$orig_p;
    }

    c$dnp3_control$block_type = "Pattern Control Block";
    c$dnp3_control$trip_control_code = control_block_trip_code[((control_code & 0xc0)/64)];
    c$dnp3_control$operation_type = control_block_operation_type[(control_code & 0xf)];
    c$dnp3_control$clear_bit = ((control_code & 0x20) >> 5) == 1;
    c$dnp3_control$execute_count = count8;
    c$dnp3_control$on_time = on_time;
    c$dnp3_control$off_time = off_time;

    if (c$dnp3_control$function_code == "RESPONSE") {
        c$dnp3_control$status_code = control_block_status_codes[status_code];    
    } else {
        delete c$dnp3_control$status_code;
    }

    Log::write(LOG_CONTROL, c$dnp3_control);
}

###################################################################################################
################  Defines logging of dnp3_object_header event -> dnp3_objects.log  ################
###################################################################################################
event dnp3_object_header(c: connection, 
                         is_orig: bool, 
                         obj_type: count, 
                         qua_field: count, 
                         number: count, 
                         rf_low: count, 
                         rf_high: count) &priority=-4{

    local device_type: string = "";
    device_type = dnp3_objects[obj_type];

    if (device_type == "unknown")
        return;

    if ( ! c?$dnp3_objects )
        c$dnp3_objects = [$ts=network_time(), $uid=c$uid, $id=c$id];

    local dnp3_object: Objects;

    dnp3_object$ts  = network_time();
    dnp3_object$uid = c$uid;
    dnp3_object$id  = c$id;
    dnp3_object$is_orig  = is_orig;

    dnp3_object$object_type = device_type;
    
    if ( is_orig ){
        dnp3_object$function_code = c$dnp3_objects$function_code;
        dnp3_object$source_h = c$id$orig_h;
        dnp3_object$source_p = c$id$orig_p;
        dnp3_object$destination_h = c$id$resp_h;
        dnp3_object$destination_p = c$id$resp_p;
        if (c$dnp3_objects$function_code != "READ")
            return;
    }
    else{
        dnp3_object$function_code = c$dnp3_objects$function_code;
        dnp3_object$source_h = c$id$resp_h;
        dnp3_object$source_p = c$id$resp_p;
        dnp3_object$destination_h = c$id$orig_h;
        dnp3_object$destination_p = c$id$orig_p;
        if (c$dnp3_objects$function_code != "RESPONSE")
            return;
        dnp3_object$object_count = number;
        dnp3_object$range_low = rf_low;
        dnp3_object$range_high = rf_high;
    }

    Log::write(LOG_OBJECTS, dnp3_object);
}

###################################################################################################
#################  Tracks the object header and prefix that point values belong to  ################
###################################################################################################
event dnp3_object_header(c: connection,
                         is_orig: bool,
                         obj_type: count,
                         qua_field: count,
                         number: count,
                         rf_low: count,
                         rf_high: count){

    if ( ! c?$dnp3_point_state )
        c$dnp3_point_state = table();

    c$dnp3_point_state[is_orig] = [$qualifier=qua_field, $range_low=rf_low];
}

event dnp3_object_prefix(c: connection,
                         is_orig: bool,
                         prefix_value: count){

    if ( c?$dnp3_point_state && is_orig in c$dnp3_point_state )
        c$dnp3_point_state[is_orig]$prefix = prefix_value;
}

###################################################################################################
#############  Builds a dnp3_point_values.log record for one point of the current object  #########
###################################################################################################
function point_value(c: connection, is_orig: bool, obj_type: count, value: double): Point_Values {

    local point: Point_Values = [$ts=network_time(), $uid=c$uid, $id=c$id];

    point$is_orig = is_orig;
    point$object_type = dnp3_objects[obj_type];
    point$value = value;

    if ( c?$dnp3_objects && c$dnp3_objects?$function_code )
        point$function_code = c$dnp3_objects$function_code;

    if ( is_orig ){
        point$source_h = c$id$orig_h;
        point$source_p = c$id$orig_p;
        point$destination_h = c$id$resp_h;
        point$destination_p = c$id$resp_p;
    }
    else{
        point$source_h = c$id$resp_h;
        point$source_p = c$id$resp_p;
        point$destination_h = c$id$orig_h;
        point$destination_p = c$id$orig_p;
    }

    if ( c?$dnp3_point_state && is_orig in c$dnp3_point_state ){
        local state = c$dnp3_point_state[is_orig];
        local prefix_code = (state$qualifier >> 4) & 0x7;
        local range_code = state$qualifier & 0xf;

        # Prefix codes 1-3 carry the point index; range codes 0-2 are start-stop ranges
        if ( prefix_code >= 1 && prefix_code <= 3 )
            point$point_index = state$prefix;
        else if ( range_code <= 2 )
            point$point_index = state$range_low + state$ordinal;

        ++state$ordinal;
    }

    return point;
}

## Zeek passes signed 16 and 32 bit values sign-extended to 64 bits
function signed_value(value: count): double {
    if ( value > 0x7fffffffffffffff )
        return 0.0 - ((0xffffffffffffffff - value) + 1);
    return value + 0.0;
}

## Zeek passes single-precision floats as their raw 32 bit pattern
function single_precision_value(bits: count): double {
    return bytestring_to_float(hexstr_to_bytestring(fmt("%08x", bits)));
}

## Zeek passes double-precision floats as the low and high 32 bits of their raw pattern
function double_precision_value(low: count, high: count): double {
    return bytestring_to_double(hexstr_to_bytestring(fmt("%08x%08x", high, low)));
}

###################################################################################################
###################  Logs Counters (group 20) values -> dnp3_point_values.log  ####################
###################################################################################################
event dnp3_counter_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count) {
    local point = point_value(c, is_orig, 0x1401, count_value + 0.0);
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_counter_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count) {
    local point = point_value(c, is_orig, 0x1402, count_value + 0.0);
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_counter_32woFlag(c: connection, is_orig: bool, count_value: count) {
    local point = point_value(c, is_orig, 0x1405, count_value + 0.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_counter_16woFlag(c: connection, is_orig: bool, count_value: count) {
    local point = point_value(c, is_orig, 0x1406, count_value + 0.0);
    Log::write(LOG_POINT_VALUES, point);
}

###################################################################################################
################  Logs Frozen Counters (group 21) values -> dnp3_point_values.log  ################
###################################################################################################
event dnp3_frozen_counter_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count) {
    local point = point_value(c, is_orig, 0x1501, count_value + 0.0);
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_counter_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count) {
    local point = point_value(c, is_orig, 0x1502, count_value + 0.0);
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_counter_32wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: count) {
    local point = point_value(c, is_orig, 0x1505, count_value + 0.0);
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_counter_16wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: count) {
    local point = point_value(c, is_orig, 0x1506, count_value + 0.0);
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_counter_32woFlag(c: connection, is_orig: bool, count_value: count) {
    local point = point_value(c, is_orig, 0x1509, count_value + 0.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_counter_16woFlag(c: connection, is_orig: bool, count_value: count) {
    local point = point_value(c, is_orig, 0x150A, count_value + 0.0);
    Log::write(LOG_POINT_VALUES, point);
}

###################################################################################################
#################  Logs Analog Inputs (group 30) values -> dnp3_point_values.log  #################
###################################################################################################
event dnp3_analog_input_32wFlag(c: connection, is_orig: bool, flag: count, value: count) {
    local point = point_value(c, is_orig, 0x1E01, signed_value(value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_16wFlag(c: connection, is_orig: bool, flag: count, value: count) {
    local point = point_value(c, is_orig, 0x1E02, signed_value(value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_32woFlag(c: connection, is_orig: bool, value: count) {
    local point = point_value(c, is_orig, 0x1E03, signed_value(value));
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_16woFlag(c: connection, is_orig: bool, value: count) {
    local point = point_value(c, is_orig, 0x1E04, signed_value(value));
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_SPwFlag(c: connection, is_orig: bool, flag: count, value: count) {
    local point = point_value(c, is_orig, 0x1E05, single_precision_value(value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_DPwFlag(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count) {
    local point = point_value(c, is_orig, 0x1E06, double_precision_value(value_low, value_high));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

###################################################################################################
#############  Logs Frozen Analog Inputs (group 31) values -> dnp3_point_values.log  ##############
###################################################################################################
event dnp3_frozen_analog_input_32wFlag(c: connection, is_orig: bool, flag: count, frozen_value: count) {
    local point = point_value(c, is_orig, 0x1F01, signed_value(frozen_value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_16wFlag(c: connection, is_orig: bool, flag: count, frozen_value: count) {
    local point = point_value(c, is_orig, 0x1F02, signed_value(frozen_value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count) {
    local point = point_value(c, is_orig, 0x1F03, signed_value(frozen_value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count) {
    local point = point_value(c, is_orig, 0x1F04, signed_value(frozen_value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_32woFlag(c: connection, is_orig: bool, frozen_value: count) {
    local point = point_value(c, is_orig, 0x1F05, signed_value(frozen_value));
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_16woFlag(c: connection, is_orig: bool, frozen_value: count) {
    local point = point_value(c, is_orig, 0x1F06, signed_value(frozen_value));
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_SPwFlag(c: connection, is_orig: bool, flag: count, frozen_value: count) {
    local point = point_value(c, is_orig, 0x1F07, single_precision_value(frozen_value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_DPwFlag(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count) {
    local point = point_value(c, is_orig, 0x1F08, double_precision_value(frozen_value_low, frozen_value_high));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

###################################################################################################
##########  Logs Analog Input Change Events (group 32) values -> dnp3_point_values.log  ###########
###################################################################################################
event dnp3_analog_input_event_32woTime(c: connection, is_orig: bool, flag: count, value: count) {
    local point = point_value(c, is_orig, 0x2001, signed_value(value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_event_16woTime(c: connection, is_orig: bool, flag: count, value: count) {
    local point = point_value(c, is_orig, 0x2002, signed_value(value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count) {
    local point = point_value(c, is_orig, 0x2003, signed_value(value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_event_16wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count) {
    local point = point_value(c, is_orig, 0x2004, signed_value(value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_event_SPwoTime(c: connection, is_orig: bool, flag: count, value: count) {
    local point = point_value(c, is_orig, 0x2005, single_precision_value(value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_event_DPwoTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count) {
    local point = point_value(c, is_orig, 0x2006, double_precision_value(value_low, value_high));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_event_SPwTime(c: connection, is_orig: bool, flag: count, value: count, time48: count) {
    local point = point_value(c, is_orig, 0x2007, single_precision_value(value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_analog_input_event_DPwTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count, time48: count) {
    local point = point_value(c, is_orig, 0x2008, double_precision_value(value_low, value_high));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

###################################################################################################
#######  Logs Frozen Analog Input Change Events (group 33) values -> dnp3_point_values.log  #######
###################################################################################################
event dnp3_frozen_analog_input_event_32woTime(c: connection, is_orig: bool, flag: count, frozen_value: count) {
    local point = point_value(c, is_orig, 0x2101, signed_value(frozen_value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_event_16woTime(c: connection, is_orig: bool, flag: count, frozen_value: count) {
    local point = point_value(c, is_orig, 0x2102, signed_value(frozen_value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count) {
    local point = point_value(c, is_orig, 0x2103, signed_value(frozen_value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_event_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count) {
    local point = point_value(c, is_orig, 0x2104, signed_value(frozen_value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_event_SPwoTime(c: connection, is_orig: bool, flag: count, frozen_value: count) {
    local point = point_value(c, is_orig, 0x2105, single_precision_value(frozen_value));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_event_DPwoTime(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count) {
    local point = point_value(c, is_orig, 0x2106, double_precision_value(frozen_value_low, frozen_value_high));
    point$flag = flag;
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_event_SPwTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count) {
    local point = point_value(c, is_orig, 0x2107, single_precision_value(frozen_value));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}

event dnp3_frozen_analog_input_event_DPwTime(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count, time48: count) {
    local point = point_value(c, is_orig, 0x2108, double_precision_value(frozen_value_low, frozen_value_high));
    point$flag = flag;
    point$point_time = double_to_time(time48 / 1000.0);
    Log::write(LOG_POINT_VALUES, point);
}
