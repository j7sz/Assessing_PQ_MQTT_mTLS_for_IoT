#!/bin/sh
# Fetch the exact upstream revisions used by the published assessment.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
third_party="$root/third_party"
mkdir -p "$third_party"

clone_pinned() {
    name=$1
    url=$2
    commit=$3
    recursive=${4:-no}
    directory="$third_party/$name"

    if [ ! -d "$directory/.git" ]; then
        git clone --no-checkout "$url" "$directory"
        git -C "$directory" checkout --detach "$commit"
        if [ "$recursive" = yes ]; then
            git -C "$directory" submodule update --init --recursive
        fi
    fi

    actual=$(git -C "$directory" rev-parse HEAD)
    if [ "$actual" != "$commit" ]; then
        echo "error: $name is at $actual; expected $commit" >&2
        echo "remove or move $directory, then rerun this script" >&2
        exit 1
    fi
    printf '%-10s %s\n' "$name" "$actual"
}

clone_pinned wolfssl https://github.com/wolfSSL/wolfssl.git \
    1d363f3adceba9d1478230ede476a37b0dcdef24
clone_pinned PQClean https://github.com/PQClean/PQClean.git \
    202a8f96315f9ed219387a50f7e40d04af037ea8
clone_pinned hawk https://github.com/hawk-sign/dev.git \
    1b9fef52559273fe7b40fe3e22968eaedd3a4c2a
clone_pinned mayo-m4 https://github.com/PQCMayo/MAYO-M4.git \
    29b14361a694ea9356198778224416aecac0ac7e yes
clone_pinned snova https://github.com/PQCLAB-SNOVA/SNOVA.git \
    9da14981336ede257c41ef53cc069989051e8181

patch="$root/tools/patches/pq_mqtt_wolfssl_tls.patch"
if git -C "$third_party/wolfssl" apply --unidiff-zero --check "$patch" 2>/dev/null; then
    git -C "$third_party/wolfssl" apply --unidiff-zero "$patch"
    echo "wolfSSL    applied project MQTT/mTLS patch"
elif git -C "$third_party/wolfssl" apply --unidiff-zero --reverse --check "$patch" 2>/dev/null; then
    echo "wolfSSL    project MQTT/mTLS patch already applied"
else
    echo "error: wolfSSL tree is neither clean nor correctly patched" >&2
    exit 1
fi
