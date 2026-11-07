#!/bin/sh
# Root checks for -U and -z (SPEC.md 16). Build first, then:
#
#   sudo sh tests/privs-root.sh [tcpflow binary]
#
# Uses the numeric ids 900:990, which need not exist, and the user nobody.
set -u
cd "$(dirname "$0")/.."
B=$(realpath "${1:-target/release/tcpflow}")
SRC=$PWD/tests
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
umask 077 # the checks must not depend on umask
W=$(mktemp -d)
chmod 755 $W
cp $SRC/test1.pcap $SRC/udp.pcap $W/ && chmod 644 $W/*.pcap
FAILS=0
ok() { echo "PASS $*"; }
bad() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
expect_owner() { # file expected label
  got=$(stat -c %u:%g "$1" 2>/dev/null || echo missing)
  [ "$got" = "$2" ] && ok "$3: $1 is $got" || bad "$3: $1 is $got, expected $2"
}
field() { awk -v f="$1:" '$1 == f { print $2 }' /proc/$2/status; }

# creds <spec> <uid> <gid> <groups> <root> [args]: the ids of the process after the drop
creds() {
  spec=$1 uid=$2 gid=$3 groups=$4 root=$5
  shift 5
  rm -f $W/fifo
  mkfifo -m 644 $W/fifo
  $B -U "$spec" "$@" -r $W/fifo 2>$W/err &
  pid=$!
  exec 3>$W/fifo
  head -c 24 $W/test1.pcap >&3 # libpcap reads the header when it opens the input; the drop follows
  sleep 0.5
  got="$(field Uid $pid)/$(field Gid $pid)/$(awk '$1 == "Groups:" { $1 = ""; print substr($0, 2) }' /proc/$pid/status | tr ' ' ,)"
  got="$got/$(field CapEff $pid)/$(readlink /proc/$pid/root)"
  caps=0000000000000000
  [ $uid = 0 ] && caps=$(field CapEff $pid) # -U :group keeps root
  want="$uid/$gid/$groups/$caps/$root"
  [ "$got" = "$want" ] && ok "-U $spec $*: $got" || bad "-U $spec $*: $got, expected $want"
  tail -c +25 $W/test1.pcap >&3
  exec 3>&-
  wait $pid || bad "-U $spec $*: exit $?: $(cat $W/err)"
}

echo "== 1. process credentials"
NOBODY_UID=$(id -u nobody)
NOBODY_GID=$(id -g nobody)
NOBODY_GROUPS=$(id -G nobody | tr ' ' '\n' | sort -n | paste -sd,)
creds 900:990 900 990 990 / -o $W/s1
creds nobody $NOBODY_UID $NOBODY_GID $NOBODY_GROUPS / -o $W/s2
creds $NOBODY_UID $NOBODY_UID $NOBODY_GID $NOBODY_GROUPS / -o $W/s3
creds :991 0 991 991 / -o $W/s4
mkdir -m 755 $W/jail
creds 900:990 900 990 990 $W/jail -z $W/jail -o out

echo
echo "== 2. created outputs are handed over"
$B -U 900:990 -o $W/out -X $W/out/report.xml -w $W/out.unk.pcap -r $W/udp.pcap -r $W/test1.pcap 2>/dev/null
for f in $W/out $W/out/report.xml $W/out.unk.pcap $W/out/074.125.019.101.00080-192.168.001.102.50956; do
  expect_owner $f 900:990 "created"
done

echo
echo "== 3. special and existing files are not given away"
before=$(stat -c '%u:%g %a' /dev/null)
$B -U 900:990 -o $W/out3 -X /dev/null -w /dev/null -r $W/udp.pcap 2>/dev/null || bad "-X /dev/null -w /dev/null: exit $?"
after=$(stat -c '%u:%g %a' /dev/null)
[ "$before" = "$after" ] && ok "/dev/null unchanged ($after)" || bad "/dev/null was $before, now $after"
touch $W/exists.pcap $W/victim && chmod 644 $W/exists.pcap $W/victim
ln -s $W/victim $W/link.xml
$B -U 900:990 -o $W/out4 -w $W/exists.pcap -X $W/link.xml -r $W/udp.pcap 2>/dev/null || bad "existing -w, symlinked -X: exit $?"
expect_owner $W/exists.pcap 0:0 "existing -w file"
[ "$(stat -c %s $W/exists.pcap)" -gt 24 ] && ok "existing -w file was written" || bad "existing -w file is empty"
expect_owner $W/victim 0:0 "symlink target of -X"
expect_owner $W/out4 900:990 "created outdir"

echo
echo "== 4. later inputs are opened as the new user"
cp $W/test1.pcap $W/secret.pcap && chmod 600 $W/secret.pcap
$B -U 900:990 -o $W/out5 -r $W/test1.pcap -r $W/test1.pcap 2>/dev/null && ok "two readable -r files" || bad "two readable -r files"
$B -U 900:990 -o $W/out6 -r $W/test1.pcap -r $W/secret.pcap 2>$W/err6
code=$?
[ $code = 1 ] && grep -q 'secret.pcap' $W/err6 && ok "unreadable second -r fails: $(cat $W/err6)" || bad "unreadable second -r: exit $code: $(cat $W/err6)"

echo
echo "== 5. -z: output directory inside the chroot"
mkdir -m 755 $W/jail2
$B -U 900:990 -z $W/jail2 -o out -r $W/test1.pcap 2>/dev/null || bad "-z: exit $?"
expect_owner $W/jail2/out 900:990 "chroot outdir"
expect_owner $W/jail2/out/report.xml 900:990 "chroot report"
expect_owner $W/jail2/out/074.125.019.101.00080-192.168.001.102.50956 900:990 "chroot flow file"
[ "$(ls $W/jail2)" = out ] && ok "only out/ in the chroot" || bad "chroot holds: $(ls $W/jail2)"

echo
echo "== 6. a uid without passwd entry needs a group"
uid=64999
while getent passwd $uid >/dev/null; do uid=$((uid - 1)); done
if $B -U $uid -o $W/out7 -r $W/test1.pcap 2>$W/err7; then
  bad "-U $uid was accepted"
else
  grep -q 'give a group' $W/err7 && ok "-U $uid: $(cat $W/err7)" || bad "-U $uid: $(cat $W/err7)"
fi

echo
echo "== 7. live capture: privileges are dropped after the device is open"
$B -U 900:990 -i lo -o $W/live -w $W/live.unk.pcap 2>$W/err8 &
pid=$!
sleep 1
got="$(field Uid $pid):$(field Gid $pid)"
[ "$got" = 900:990 ] && ok "capturing as $got" || bad "capturing as $got: $(cat $W/err8)"
kill -INT $pid
wait $pid
code=$?
[ $code = 0 ] && ok "SIGINT stops the capture" || bad "exit $code after SIGINT: $(cat $W/err8)"
expect_owner $W/live/report.xml 900:990 "live report"
expect_owner $W/live.unk.pcap 900:990 "live -w file"

rm -rf $W
echo
echo "FAILURES: $FAILS"
[ $FAILS = 0 ]
