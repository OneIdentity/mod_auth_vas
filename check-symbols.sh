#!/bin/sh
# Copyright & License at end of file.
set -e

usage () {
    echo "Usage: $0 <pattern> <module> [module...]"
    echo "  <pattern> describes symbols that are expected and is passed to 'grep -E'"
}

case "$1" in
    -h|--help)
	usage
	exit 0
    ;;
esac

if [ $# -lt 2 ]; then
    usage >&2
    exit 2
fi

# Symbols to consider safely namespaced
ALLOW_PATTERN="$1"

found_leaks=no

while [ $# -gt 1 ]; do
    shift
    MODULE="$1"

    # Find Initialized (D)ata, (T)ext, (B)SS (zeroed) and (R)ead-only dynamic
    # symbols. _init and _fini are always ignored.
    syms=`nm -D --defined-only -- "$MODULE" | cut -d' ' -f2- | grep -E '^(D|T|B|R)' | \
        grep -Ev -- "$ALLOW_PATTERN" | grep -Ev '^T _(init|fini)$' | \
        grep -Ev '^B _(_bss_start|end)$' | grep -Ev '^D _edata' || true`

    if [ "$syms" != "" ]; then
	echo >&2
	echo "Found unexpected symbols in $MODULE:" >&2
	echo "$syms" >&2
	found_leaks=yes
    fi
done

if [ $found_leaks = yes ]; then
    exit 1
fi

exit 0

#  Copyright 2017 Quest Software, Inc. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  
#  a. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  b. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  c. Neither the name of Quest Software, Inc. nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
