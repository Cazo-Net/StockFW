# bash completion for stockfw(1).
#
# A thin wrapper: stockfw itself prints the words that fit
# (`stockfw __complete WORD...'), from the same tables its parser reads,
# so this file never needs to change when a command or option does.
# Installed as share/bash-completion/completions/stockfw.

_stockfw()
{
    local line=${COMP_LINE:0:COMP_POINT} cur tail pre c
    local -a words cands
    local IFS=$' \t\n'

    # The words up to the cursor, split on blanks (quotes are not
    # undone); a blank at the end starts a new, empty word.
    read -r -a words <<< "$line"
    if [[ -z $line || $line == *[[:blank:]] ]]; then
        words+=("")
    fi
    (( ${#words[@]} >= 2 )) || return 0
    cur=${words[${#words[@]}-1]}

    IFS=$'\n'
    cands=($(command "${words[0]}" __complete "${words[@]:1}" 2>/dev/null))
    IFS=$' \t\n'

    # Readline replaces only the part of the word after its last = or :
    # (both are in COMP_WORDBREAKS by default), so each candidate loses
    # what comes before it: --by=src and inbound-allow-service:2 work.
    tail=$cur
    for c in = :; do
        if [[ $COMP_WORDBREAKS == *"$c"* ]]; then
            tail=${tail##*"$c"}
        fi
    done
    pre=${cur%"$tail"}
    COMPREPLY=()
    for c in "${cands[@]}"; do
        [[ $c == "$pre"* ]] && COMPREPLY+=("${c#"$pre"}")
    done
    return 0
}
complete -o default -F _stockfw stockfw
