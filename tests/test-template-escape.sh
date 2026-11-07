#!/bin/sh
#
# test that a literal "%%c" in -T does not count as the connection counter
#

. $srcdir/test-subs.sh

OUT=out-template-escape

rm -rf $OUT
# all four flows expand to the same name; without a counter this never ends
if ! timeout -s KILL 30 $TCPFLOW -o $OUT -T 'x%%c' -r $DMPDIR/test1.pcap ; then
  echo "failure: tcpflow -T 'x%%c' did not finish"
  exit 1
fi
if [ ! -f "$OUT/x%c" ] || [ ! -f "$OUT/x%cc1" ] ; then
  echo "failure: the counter was not appended"
  ls $OUT
  exit 1
fi

rm -rf $OUT
exit 0
