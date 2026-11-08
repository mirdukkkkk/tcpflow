# bash completion for tcpflow
# generated from src/cli.rs by `cargo run --example completions`; do not edit

_tcpflow() {
    local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]} w
    COMPREPLY=()
    case $prev in
        -r|-R|-X|-w)
            COMPREPLY=($(compgen -f -- "$cur"))
            return ;;
        -o|-z)
            COMPREPLY=($(compgen -d -- "$cur"))
            return ;;
        -i)
            COMPREPLY=($(compgen -W "$(ls /sys/class/net 2>/dev/null || ifconfig -l 2>/dev/null)" -- "$cur"))
            return ;;
        -U)
            COMPREPLY=($(compgen -u -- "$cur"))
            return ;;
        -e|-x|-E)
            COMPREPLY=($(compgen -W "http md5 all" -- "$cur"))
            return ;;
        -S)
            compopt -o nospace
            COMPREPLY=($(compgen -W "enable_report= tdelta= tcp_timeout= tcp_cmd= http_cmd= tcp_alert_fd= http_alert_fd= http_max_body= packet-buffer-timeout=" -- "$cur"))
            return ;;
        -T|-F|-b|-m|-f|-L|-d)
            return ;;
    esac
    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "-r -R -l -i -p -o -T -F -b -m -f -X -c -C -D -B -s -0 -g -J -L -I -K -w -a -e -x -E -Z -S -U --relinquish-privileges -z --chroot -q -d -v --verbose -V --version -h --help" -- "$cur"))
        return
    fi
    # with -l the remaining arguments are capture files, else a filter expression
    for w in "${COMP_WORDS[@]}"; do
        if [[ $w == -l ]]; then
            COMPREPLY=($(compgen -f -- "$cur"))
            return
        fi
    done
}
complete -o filenames -F _tcpflow tcpflow
