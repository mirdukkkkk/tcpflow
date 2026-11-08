//! Shell completions for bash, zsh and fish, generated from the option table in
//! `cli.rs`. `cargo run --example completions` writes them to `doc/completions/`;
//! a test checks that the files there are up to date.

use crate::cli::{F_FLAGS, OPTIONS, PARAMS, POST_PROCESSORS, Value};

const HEADER: &str = "generated from src/cli.rs by `cargo run --example completions`; do not edit";

/// The file name and content of every completion file.
pub fn all() -> [(&'static str, String); 3] {
    [
        ("tcpflow.bash", bash()),
        ("_tcpflow", zsh()),
        ("tcpflow.fish", fish()),
    ]
}

fn letters(kinds: &[Value]) -> Vec<String> {
    OPTIONS
        .iter()
        .filter(|o| o.value.is_some_and(|(_, k)| kinds.contains(&k)))
        .map(|o| format!("-{}", o.letter))
        .collect()
}

pub fn bash() -> String {
    let all: Vec<String> = OPTIONS
        .iter()
        .flat_map(|o| {
            let mut v = vec![format!("-{}", o.letter)];
            v.extend(o.long.map(|l| format!("--{l}")));
            v
        })
        .collect();
    let params: Vec<String> = PARAMS.iter().map(|p| format!("{}=", p.name)).collect();
    let posts: Vec<&str> = POST_PROCESSORS.iter().map(|p| p.0).collect();
    let case = |kinds: &[Value]| letters(kinds).join("|");
    format!(
        r#"# bash completion for tcpflow
# {HEADER}

_tcpflow() {{
    local cur=${{COMP_WORDS[COMP_CWORD]}} prev=${{COMP_WORDS[COMP_CWORD-1]}} w
    COMPREPLY=()
    case $prev in
        {files})
            COMPREPLY=($(compgen -f -- "$cur"))
            return ;;
        {dirs})
            COMPREPLY=($(compgen -d -- "$cur"))
            return ;;
        {ifaces})
            COMPREPLY=($(compgen -W "$(ls /sys/class/net 2>/dev/null || ifconfig -l 2>/dev/null)" -- "$cur"))
            return ;;
        {users})
            COMPREPLY=($(compgen -u -- "$cur"))
            return ;;
        {posts_opts})
            COMPREPLY=($(compgen -W "{posts}" -- "$cur"))
            return ;;
        {params_opts})
            compopt -o nospace
            COMPREPLY=($(compgen -W "{params}" -- "$cur"))
            return ;;
        {other})
            return ;;
    esac
    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "{all}" -- "$cur"))
        return
    fi
    # with -l the remaining arguments are capture files, else a filter expression
    for w in "${{COMP_WORDS[@]}}"; do
        if [[ $w == -l ]]; then
            COMPREPLY=($(compgen -f -- "$cur"))
            return
        fi
    done
}}
complete -o filenames -F _tcpflow tcpflow
"#,
        files = case(&[Value::File]),
        dirs = case(&[Value::Dir]),
        ifaces = case(&[Value::Interface]),
        users = case(&[Value::User]),
        posts_opts = case(&[Value::PostProcessor]),
        posts = posts.join(" "),
        params_opts = case(&[Value::Param]),
        params = params.join(" "),
        other = case(&[Value::Flags, Value::Number, Value::Text]),
        all = all.join(" "),
    )
}

/// Escape for a single-quoted zsh word inside `_arguments` brackets.
fn zsh_text(s: &str) -> String {
    s.replace('\'', r"'\''")
        .replace('[', r"\[")
        .replace(']', r"\]")
        .replace(':', r"\:")
}

/// Escape for a single-quoted `name:description` item of `_describe`.
fn zsh_item(s: &str) -> String {
    s.replace('\'', r"'\''").replace(':', r"\:")
}

pub fn zsh() -> String {
    let mut specs = Vec::new();
    for o in OPTIONS {
        let star = if o.repeatable { "*" } else { "" };
        let help = zsh_text(o.help);
        let arg = match o.value {
            None => String::new(),
            Some((name, kind)) => {
                let action = match kind {
                    Value::File => "_files",
                    Value::Dir => "_files -/",
                    Value::Interface => "_net_interfaces",
                    Value::User => "_users",
                    Value::Param => "_tcpflow_params",
                    Value::PostProcessor => "_tcpflow_post",
                    Value::Flags => "_tcpflow_flags",
                    Value::Number | Value::Text => " ",
                };
                format!(":{}:{action}", zsh_text(name))
            }
        };
        // + : the argument may follow the letter directly (-r-) or be the next word
        let plus = if o.value.is_some() { "+" } else { "" };
        specs.push(format!("'{star}-{}{plus}[{help}]{arg}'", o.letter));
        if let Some(long) = o.long {
            let eq = if o.value.is_some() { "=" } else { "" };
            specs.push(format!("'{star}--{long}{eq}[{help}]{arg}'"));
        }
    }
    specs.push("'*:filter expression, or capture files with -l:_files'".into());
    let described = |items: Vec<(String, &str)>| -> String {
        items
            .iter()
            .map(|(n, h)| format!("    '{}:{}'", zsh_item(n), zsh_item(h)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let params = described(
        PARAMS
            .iter()
            .map(|p| (format!("{}=", p.name), p.help))
            .collect(),
    );
    let posts = described(
        POST_PROCESSORS
            .iter()
            .map(|p| (p.0.to_string(), p.1))
            .collect(),
    );
    let flags = described(F_FLAGS.iter().map(|(c, h)| (c.to_string(), *h)).collect());
    format!(
        r#"#compdef tcpflow
# zsh completion for tcpflow
# {HEADER}

_tcpflow_params() {{
  local -a params=(
{params}
  )
  _describe -t parameters 'parameter' params -S ''
}}

_tcpflow_post() {{
  local -a names=(
{posts}
  )
  _describe -t post-processors 'post-processor' names
}}

# -F takes several flags in one word (-Fct): complete one more letter
_tcpflow_flags() {{
  local -a flags=(
{flags}
  )
  compset -P '*'
  _describe -t flags 'flag' flags -S ''
}}

_arguments -s -S \
  {specs}
"#,
        specs = specs.join(" \\\n  "),
    )
}

/// Escape for a single-quoted fish word.
fn fish_text(s: &str) -> String {
    s.replace('\\', r"\\").replace('\'', r"\'")
}

pub fn fish() -> String {
    let mut lines = vec![
        "# fish completion for tcpflow".to_string(),
        format!("# {HEADER}"),
        String::new(),
        "# the arguments after the options are a filter expression, or files with -l".into(),
        "complete -c tcpflow -f".into(),
        "complete -c tcpflow -n '__fish_contains_opt -s l' -F".into(),
    ];
    for o in OPTIONS {
        let mut c = format!("complete -c tcpflow -s {}", o.letter);
        if let Some(long) = o.long {
            c.push_str(&format!(" -l {long}"));
        }
        let help = fish_text(o.help);
        match o.value.map(|v| v.1) {
            None => lines.push(format!("{c} -d '{help}'")),
            Some(Value::File) => lines.push(format!("{c} -r -F -d '{help}'")),
            Some(Value::Dir) => lines.push(format!(
                "{c} -x -a '(__fish_complete_directories)' -d '{help}'"
            )),
            Some(Value::Interface) => {
                lines.push(format!("{c} -x -a '(__fish_print_interfaces)' -d '{help}'"))
            }
            Some(Value::User) => {
                lines.push(format!("{c} -x -a '(__fish_complete_users)' -d '{help}'"))
            }
            Some(Value::Number | Value::Text) => lines.push(format!("{c} -x -d '{help}'")),
            Some(Value::Param) => {
                for p in PARAMS {
                    lines.push(format!(
                        "{c} -x -a '{}=' -d '{}'",
                        p.name,
                        fish_text(p.help)
                    ));
                }
            }
            Some(Value::PostProcessor) => {
                for (name, h) in POST_PROCESSORS {
                    lines.push(format!("{c} -x -a '{name}' -d '{}'", fish_text(h)));
                }
            }
            Some(Value::Flags) => {
                for (flag, h) in F_FLAGS {
                    lines.push(format!("{c} -x -a '{flag}' -d '{}'", fish_text(h)));
                }
            }
        }
    }
    lines.push(String::new());
    lines.join("\n")
}
