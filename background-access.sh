#!/bin/sh
# Optional, explicit setup only. Ordinary installation and ccguard-kill never run this.
set -eu
case "${1-}" in
    enable|disable) [ "$#" -eq 1 ] || exit 2 ;;
    *) printf '%s\n' '用法: bash background-access.sh enable|disable'; exit 2 ;;
esac
[ "$(/usr/bin/uname -s)" = Darwin ] || { echo '仅支持 macOS。' >&2; exit 1; }
ccguard_uid=$(/usr/bin/id -u)
[ "$ccguard_uid" -ne 0 ] || { echo '请以日常使用的用户运行，不要在命令前加 sudo。' >&2; exit 1; }
if [ "$1" = enable ]; then
    printf '%s\n' '将授权当前用户免密执行 /usr/bin/sfltool dumpbtm（只读系统后台项目清单）。' \
        '只解析当前用户的 Claude 权限；不授权其他命令，不保存密码。配置时由 sudo 请求一次管理员认证。'
else
    printf '%s\n' '将撤销 CCGuard 的免密只读授权；不修改 Claude 的后台开关。'
fi
# Password is handled by sudo on the user's terminal, never stdin or CCGuard.
/usr/bin/sudo /bin/sh -s -- "$1" "$ccguard_uid" <<'CCGUARD_ROOT'
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(/usr/bin/id -u)" -eq 0 ] || fail '需要管理员授权。'
[ "$#" -eq 2 ] || fail '参数无效。'
action=$1
ccguard_uid=$2
case "$action" in enable|disable) ;; *) fail '操作无效。';; esac
case "$ccguard_uid" in ''|0|*[!0-9]*) fail '用户 ID 无效。';; esac
[ "${SUDO_UID-}" = "$ccguard_uid" ] || fail '用户 ID 与授权用户不一致。'

rules=/private/etc/sudoers.d
master=/private/etc/sudoers
target=$rules/ccguard-btm-$ccguard_uid
[ -d "$rules" ] && [ ! -L "$rules" ] || fail 'sudoers.d 不是受支持的真实目录；未修改。'
case "$(/usr/bin/stat -f '%u:%g:%Lp' "$rules")" in
    0:0:755|0:0:750|0:0:700) ;; *) fail 'sudoers.d 归属或权限不符合要求；未修改。';;
esac
[ -f "$master" ] && [ ! -L "$master" ] || fail 'sudoers 主文件异常；未修改。'
/usr/bin/grep -Eq '^[[:space:]]*[@#]includedir[[:space:]]+(/private)?/etc/sudoers\.d/?[[:space:]]*(#.*)?$' "$master" \
    || fail '系统未启用标准 sudoers.d 目录；不自动修改全局授权配置。'
/usr/sbin/visudo -c -f "$master" >/dev/null || fail '现有 sudoers 配置未通过校验；未修改。'

temporary=$(/usr/bin/mktemp "$rules/.ccguard-btm-$ccguard_uid.XXXXXX")
rollback=none
cleanup() {
    case "$rollback" in
        remove) /bin/rm -f "$target" ;;
        restore) /bin/mv -f "$temporary" "$target" ;;
    esac
    /bin/rm -f "$temporary"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
printf '# Managed by ccguard-background-access-v1\n# Read-only BTM query for UID %s\n#%s ALL=(root) NOPASSWD: NOSETENV: /usr/bin/sfltool dumpbtm\n' \
    "$ccguard_uid" "$ccguard_uid" > "$temporary"
/usr/sbin/chown root:wheel "$temporary"
/bin/chmod 0440 "$temporary"
/usr/sbin/visudo -c -f "$temporary" >/dev/null || fail '只读授权规则未通过语法校验；未修改。'

[ ! -L "$target" ] || fail '同名规则是符号链接；已保留且停止。'
if [ -e "$target" ]; then
    [ -f "$target" ] || fail '同名规则不是普通文件；已保留且停止。'
    [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$target")" = 0:0:440 ] \
        || fail '同名规则归属或权限异常；已保留且停止。'
    /usr/bin/cmp -s "$temporary" "$target" || fail '同名规则不是本工具的准确内容；已保留且停止。'
    if [ "$action" = enable ]; then
        printf '%s\n' '只读授权已存在，无需重复配置。'
        exit 0
    fi
    rollback=restore
    /bin/rm "$target"
else
    if [ "$action" = disable ]; then
        printf '%s\n' '未发现本用户的只读授权，无需撤销。'
        exit 0
    fi
    rollback=remove
    /bin/mv "$temporary" "$target"
fi
/usr/sbin/visudo -c -f "$master" >/dev/null || fail '整体配置校验失败，回滚本次授权变更。'
rollback=none
if [ "$action" = enable ]; then
    printf '%s\n' '已配置持久只读授权。后续 ccguard-kill 会实时读取后台权限，无需再次输入密码。'
else
    printf '%s\n' '已撤销只读授权。ccguard-kill 继续清理进程，但不再读取后台开关。'
fi
CCGUARD_ROOT
