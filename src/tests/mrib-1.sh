#!/bin/sh

for i in `seq 1 9999`; do
	$1 mrib prefix 2001:$i::/32 via 2001:$i::1 metric $i
done

