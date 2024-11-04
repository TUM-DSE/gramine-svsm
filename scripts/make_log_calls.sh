#!/bin/bash

output_file="log_calls.gdb"

function_names=(
    # pal_console.c
    "console_open"
    "console_read"
    "console_write"
    "console_destroy"
    "console_flush"

    # pal_devices.c
    "dev_open"
    "dev_read"
    "dev_write"
    "dev_destroy"
    "dev_delete"
    "dev_setlength"
    "dev_flush"
    "dev_attrquery"
    "dev_attrquerybyhdl"
    "dev_map"
    "_PalDeviceIoControl"

    # pal_eventfd.c
    "eventfd_pal_open"
    "eventfd_pal_read"
    "eventfd_pal_write"
    "eventfd_pal_attrquerybyhdl"
    "eventfd_pal_destroy"

    # pal_events.c
    "_PalEventCreate"
    "_PalEventSet"
    "_PalEventClear"
    "_PalEventWait"
    "event_destroy"

    # pal_exception.c

    # pal_files.c
    "file_open"
    "file_read"
    "file_write"
    "file_destroy"
    "file_delete"
    "file_map"
    "file_setlength"
    "file_flush"
    "file_attrquery"
    "file_attrquerybyhdl"
    "file_rename"
    "dir_open"
    "dir_read"
    "dir_destroy"
    "dir_delete"
    "dir_attrquerybyhdl"
    "dir_rename"

    # pal_memory.c
    "_PalVirtualMemoryAlloc"
    "_PalVirtualMemoryFree"
    "_PalVirtualMemoryProtect"
    "_PalMemoryQuota"
    "pal_read_next_reserved_range"

    # pal_misc.c
    "_PalSystemTimeQuery"
    "_PalRandomBitsRead"
    "_PalSegmentBaseGet"
    "_PalSegmentBaseSet"
    "_PalCpuIdRetrieve"
    "_PalAttestationReport"
    "_PalAttestationQuote"
    "_PalGetSpecialKey"
    "_PalGetBogomips"

    # pal_object.c
    "_PalStreamsWaitEvents"

    # pal_pipes.c
    "pipe_listen"
    "pipe_waitforclient"
    "pipe_connect"
    "pipe_open"
    "pipe_read"
    "pipe_write"
    "pipe_destroy"
    "pipe_delete"

    # pal_process.c
    "_PalProcessCreate"
    "_PalProcessExit"
    "proc_read"
    "proc_write"
    "proc_destroy"

    # pal_rtld.c
    "_PalDebugMapAdd"
    "_PalDebugMapRemove"
    "_PalDebugDescribeLocation"

    # pal_sockets.c
    "_PalSocketCreate"
    "_PalSocketBind"
    "_PalSocketListen"
    "_PalSocketAccept"
    "_PalSocketConnect"
    "_PalSocketSend"
    "_PalSocketRecv"

    # pal_streams.c
    "_PalSendHandle"
    "_PalReceiveHandle"
    "_PalInitDebugStream"
    "_PalDebugLog"

    # pal_threading.c
    "_PalThreadCreate"
    "_PalThreadYieldExecution"
    "_PalThreadExit"
    "_PalThreadResume"
    "_PalThreadSetCpuAffinity"
    "_PalThreadGetCpuAffinity"
)

# Clear the output file if it exists
> "$output_file"

# Loop through the values and write the interpolated string to the file
for function in "${function_names[@]}"; do
    echo "break $function" >> "$output_file"
    echo "commands" >> "$output_file"
    echo "silent" >> "$output_file"
    echo "printf \"$function called\\n\"" >> "$output_file"
    # echo "backtrace 1" >> "$output_file"
    echo "continue" >> "$output_file"
    echo "end" >> "$output_file"
    echo "" >> "$output_file"
done

# Add the logging commands at the end of the file
echo "set logging file gdb.log" >> "$output_file"
echo "set logging enabled on" >> "$output_file"
echo "" >> "$output_file"
echo "run" >> "$output_file"

echo "File '$output_file' has been created. Run it in GDB with 'source $output_file'."
