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
                            LOG_OBJECTS };

    ###############################################################################################
    ################################  Control -> dnp3_control.log  ################################
    ###############################################################################################
    type Control: record {
        ts                      : time      &log;             # Timestamp of event
        uid                     : string    &log;             # Zeek unique ID for connection
        id                      : conn_id   &log;             # Zeek connection struct (addresses and ports)
        is_orig                 : bool      &optional &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &optional &log;   # Source IP Address
        source_p                : port      &optional &log;   # Source Port
        destination_h           : addr      &optional &log;   # Destination IP Address
        destination_p           : port      &optional &log;   # Destination Port
        block_type              : string    &optional &log;   # Control_Relay_Output_Block or Pattern_Control_Block
        function_code           : string    &optional &log;   # Function Code (SELECT, OPERATE, RESPONSE)
        index_number            : count     &optional &log;   # Object Index #
        trip_control_code       : string    &optional &log;   # Nul, Close, or Trip
        operation_type          : string    &optional &log;   # Nul, Pulse_On, Pulse_Off, Latch_On, Latch_Off
        execute_count           : count     &optional &log;   # Number of times to execute
        on_time                 : count     &optional &log;   # On Time
        off_time                : count     &optional &log;   # Off Time
        status_code             : string    &optional &log;   # Status Code (see control_block_status_codes)
    };
    global log_control: event(rec: Control);

    ###############################################################################################
    ################################  Objects -> dnp3_objects.log  ################################
    ###############################################################################################
    type Objects: record {
        ts                      : time      &log;             # Timestamp of event
        uid                     : string    &log;             # Zeek unique ID for connection
        id                      : conn_id   &log;             # Zeek connection struct (addresses and ports)
        is_orig                 : bool      &optional &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &optional &log;   # Source IP Address
        source_p                : port      &optional &log;   # Source Port
        destination_h           : addr      &optional &log;   # Destination IP Address
        destination_p           : port      &optional &log;   # Destination Port
        function_code           : string    &optional &log;   # Function Code (READ or RESPONSE)
        object_type             : string    &optional &log;   # Object type (see dnp3_objects)
        object_count            : count     &optional &log;   # Number of objects
        range_low               : count     &optional &log;   # Range (Low) of object
        range_high              : count     &optional &log;   # Range (High) of object
    };
    global log_objects: event(rec: Objects);
}

redef record connection += {
    dnp3_control: Control &optional;
    dnp3_objects: Objects &optional;
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
}

###################################################################################################
##################  Initializes the dnp3_control object for a new control event ###################
###################################################################################################
event dnp3_object_prefix(c: connection, 
                         is_orig: bool, 
                         prefix_value: count){

    if ( ! c?$dnp3_control )
        c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];
    
    c$dnp3_control$index_number = prefix_value;

    # Reset fields for new data
    delete c$dnp3_control$block_type;
    delete c$dnp3_control$trip_control_code;
    delete c$dnp3_control$operation_type;
    delete c$dnp3_control$execute_count;
    delete c$dnp3_control$on_time;
    delete c$dnp3_control$off_time;
    delete c$dnp3_control$status_code;
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
    c$dnp3_control$execute_count = count8;
    c$dnp3_control$on_time = on_time;
    c$dnp3_control$off_time = off_time;
    c$dnp3_control$status_code = control_block_status_codes[status_code];    

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
    c$dnp3_control$execute_count = count8;
    c$dnp3_control$on_time = on_time;
    c$dnp3_control$off_time = off_time;
    c$dnp3_control$status_code = control_block_status_codes[status_code];

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