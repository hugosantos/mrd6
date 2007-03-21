#!/bin/sh
for t in tests/*_unittest; do
	if [ -x $t ]; then
		N=`basename $t`
		echo "  --- Running $N ---"
		$t
	fi
done
