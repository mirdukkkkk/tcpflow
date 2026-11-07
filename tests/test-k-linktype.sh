#!/bin/sh
#
# test that -K writes Ethernet captures with the Ethernet link type (1)
#

. $srcdir/test-subs.sh

rm -rf out-k
cmd "$TCPFLOW -K -o out-k -r $DMPDIR/test1.pcap"
for f in out-k/*.pcap ; do
  linktype=`od -An -t u4 -j 20 -N 4 $f | tr -d ' '`
  if [ x"$linktype" != x"1" ] ; then
    echo "failure: $f has link type $linktype, expected 1 (Ethernet)"
    exit 1
  fi
done

rm -rf out-k
exit 0
