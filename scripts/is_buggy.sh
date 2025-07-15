#!/bin/bash

vmlinux=$1

# TODO: add check for the existence of uretprobe syscall when testing before 6.11

objdump -t $vmlinux 2> /dev/null | grep seccomp_cache_prepare_bitmap | cut -d ' ' -f 1 | sort > syms
echo "'seccomp_cache_prepare_bitmap' symbol addresses: $(cat syms)"

sym_addr_ls_len=$(cat syms | wc -l)
echo "number of addresses found: $sym_addr_ls_len"

first_sym=$(head -n 1 syms)
echo "Bytecode dump start: $first_sym"

end_sym=$(objdump -t $vmlinux 2> /dev/null | cut -d ' ' -f 1 | sort | grep -A $sym_addr_ls_len $first_sym | tail -n 1)
echo "Bytecode dump end: $end_sym"

text_offset=$(readelf -l --wide $vmlinux 2> /dev/null | grep LOAD | head -n 1 | tr -s "[:blank:]" | cut -d ' ' -f 3)
let "num_bytes = 0x$end_sym - 0x$first_sym"
let "skip_bytes = 0x$first_sym - 0xffffffff81000000 + $text_offset"
echo "CMD: dd if=$vmlinux of=bits bs=1 count=$num_bytes skip=$skip_bytes"
dd if=$vmlinux of=bits bs=1 count=$num_bytes skip=$skip_bytes

xxd bits | grep -q "4f01"
status=$?
[ $status -ne 0 ] && exit 13
