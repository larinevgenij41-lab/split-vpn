#!/usr/bin/bash
# Сборка нативных зависимостей AnyConnect по third_party/openconnect/manifest.json в MSYS2 UCRT64:
# libopenconnect (из исходников), ocshim, закреплённые пакеты-зависимости, wintun.
# Результат — third_party/openconnect/bin: DLL, licenses/, SHA256SUMS.txt (каталог не в git).
# Запуск из PowerShell: $env:MSYSTEM='UCRT64'; C:\msys64\usr\bin\bash.exe -l /d/VPN/scripts/build-openconnect.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/third_party/openconnect/manifest.json"
WORK="$ROOT/third_party/openconnect/work"
CACHE="$WORK/cache"
STAGE="$WORK/stage"
OUT="$ROOT/third_party/openconnect/bin"
P=mingw-w64-ucrt-x86_64

fail() { echo "ОШИБКА: $*" >&2; exit 1; }
# jq из UCRT64 завершает строки CRLF: CR срезается, иначе ломаются хеши и пути.
jqr() { jq -r "$@" | tr -d '\015'; }

echo "== инструменты сборки"
pacman -S --noconfirm --needed base-devel autotools unzip $P-jq $P-gcc $P-pkgconf $P-ntldd > /tmp/oc-tools.log 2>&1 \
  || { tail -n 20 /tmp/oc-tools.log; fail "не удалось установить инструменты"; }
mkdir -p "$CACHE"

# Файл в кэше с проверкой SHA-256; скачивается, если его нет или хеш не совпал.
fetch() {
  local url=$1 file=$2 sha=$3
  if [ ! -f "$CACHE/$file" ] || ! echo "$sha  $CACHE/$file" | sha256sum -c --status -; then
    rm -f "$CACHE/$file"
    curl -fsSL "$url" -o "$CACHE/$file" || fail "не скачан $url"
  fi
  echo "$sha  $CACHE/$file" | sha256sum -c --status - || fail "хеш не совпал: $file"
}

echo "== закреплённые пакеты"
REPO=$(jqr '.msys2Repository' "$MANIFEST")
jqr '.packages[] | "\(.name) \(.version) \(.sha256)"' "$MANIFEST" | while read -r name version sha; do
  file="$name-$version-any.pkg.tar.zst"
  if [ -f "/var/cache/pacman/pkg/$file" ] && [ ! -f "$CACHE/$file" ]; then
    cp "/var/cache/pacman/pkg/$file" "$CACHE/$file"
  fi
  fetch "$REPO$file" "$file" "$sha"
  installed=$(pacman -Q "$name" 2>/dev/null | cut -d' ' -f2 || true)
  if [ "$installed" != "$version" ]; then
    echo "   $name: установлено «${installed:-нет}», нужно $version"
    pacman -U --noconfirm "$CACHE/$file" > /tmp/oc-pin.log 2>&1 || { tail -n 20 /tmp/oc-pin.log; fail "не установлен $file"; }
  fi
  echo "   $name $version"
done

echo "== исходники"
OC_VERSION=$(jqr '.openconnect.version' "$MANIFEST")
fetch "$(jqr '.openconnect.source' "$MANIFEST")" "openconnect-$OC_VERSION.tar.gz" "$(jqr '.openconnect.sha256' "$MANIFEST")"
WINTUN_VERSION=$(jqr '.wintun.version' "$MANIFEST")
fetch "$(jqr '.wintun.source' "$MANIFEST")" "wintun-$WINTUN_VERSION.zip" "$(jqr '.wintun.sha256' "$MANIFEST")"

SRC="$WORK/openconnect-$OC_VERSION"
rm -rf "$SRC" "$STAGE"
tar xzf "$CACHE/openconnect-$OC_VERSION.tar.gz" -C "$WORK"
cd "$SRC"
# Новые заголовки mingw-w64 не содержат sec_api/: объявления есть в stdlib.h
sed -i "s|^#include <sec_api/stdlib_s.h>.*|#include <stdlib.h>|" compat.c
if grep -q "sec_api" compat.c; then fail "правка compat.c не применилась"; fi
# Проверенный архив wintun: иначе make скачает его сам без проверки хеша
cp "$CACHE/wintun-$WINTUN_VERSION.zip" "$SRC/"

echo "== configure"
./configure --prefix="$STAGE" --with-vpnc-script=vpnc-script-win.js --disable-nls --without-openssl --with-gnutls \
  --without-stoken --without-libpcsclite --without-libproxy --without-gssapi --disable-docs \
  > /tmp/oc-conf.log 2>&1 || { tail -n 40 /tmp/oc-conf.log; fail "configure"; }
grep -qE 'DTLS support: +yes' /tmp/oc-conf.log || fail "DTLS не включён"

echo "== make"
make -j8 > /tmp/oc-make.log 2>&1 || { tail -n 40 /tmp/oc-make.log; fail "make"; }
make install > /tmp/oc-inst.log 2>&1 || { tail -n 20 /tmp/oc-inst.log; fail "make install"; }

echo "== ocshim"
gcc -O2 -Wall -Wextra -Werror -shared -o "$STAGE/bin/ocshim.dll" "$ROOT/native/ocshim/ocshim.c" \
  -I"$STAGE/include" -L"$STAGE/bin" -lopenconnect-5 -lws2_32

echo "== выкладка"
rm -rf "$OUT"
mkdir -p "$OUT/licenses"
cp "$STAGE/bin/libopenconnect-5.dll" "$STAGE/bin/ocshim.dll" "$OUT/"
unzip -p "$CACHE/wintun-$WINTUN_VERSION.zip" wintun/bin/amd64/wintun.dll > "$OUT/wintun.dll"
jqr '.packages[].dlls[]' "$MANIFEST" | while read -r dll; do
  cp "/ucrt64/bin/$dll" "$OUT/" || fail "нет /ucrt64/bin/$dll"
done

# Замыкание: всё, что libopenconnect и ocshim тянут из MSYS2, должно быть в манифесте.
expected=$(jqr '[.openconnect.dlls[], .ocshim.dlls[], .wintun.dlls[], .packages[].dlls[]] | .[]' "$MANIFEST" | tr 'A-Z' 'a-z' | sort -u)
# ntldd печатает «имя => путь» или, для DLL из той же папки, просто «имя (адрес)»: системные (C:\Windows) и неразрешённые api-set пропускаются.
actual=$( (cd "$OUT" && ntldd -R libopenconnect-5.dll ocshim.dll || true) | grep -E '^\s' | grep -viE '=> not found|=> [a-z]:.windows.' \
  | awk '{print $1}' | tr 'A-Z' 'a-z' | sort -u)
for dll in $actual; do
  echo "$expected" | grep -qx "$dll" || fail "зависимость не описана в манифесте: $dll"
done
for dll in $expected; do
  [ -f "$OUT/$dll" ] || [ -f "$OUT/$(ls "$OUT" | grep -ix "$dll")" ] || fail "не выложен $dll"
done

echo "== лицензии"
LIC="$OUT/licenses"
cp "$SRC/COPYING.LGPL" "$LIC/LGPL-2.1.txt"
cp /ucrt64/share/licenses/binutils/COPYING3.LIB "$LIC/LGPL-3.0.txt"
cp /ucrt64/share/licenses/binutils/COPYING3 "$LIC/GPL-3.0.txt"
cp /ucrt64/share/licenses/binutils/COPYING "$LIC/GPL-2.0.txt"
unzip -p "$CACHE/wintun-$WINTUN_VERSION.zip" wintun/LICENSE.txt > "$LIC/wintun-LICENSE.txt"
for pkg in brotli libffi libiconv libtasn1 libunistring libwinpthread libxml2 zstd zlib gettext-runtime; do
  dir=/ucrt64/share/licenses/$pkg
  [ -d "$dir" ] || fail "нет лицензии пакета $pkg"
  (cd "$dir" && find . -type f) | while read -r file; do
    cp "$dir/$file" "$LIC/$pkg-$(echo "${file#./}" | tr '/' '-').txt"
  done
done
cp /usr/share/licenses/p11-kit/COPYING "$LIC/p11-kit-COPYING.txt"
cat > "$LIC/README.txt" <<EOF
Нативные компоненты протокола AnyConnect в «Раздельном VPN».
Точные версии, хеши архивов и адреса исходников — third_party/openconnect/manifest.json в исходниках программы.

OpenConnect $OC_VERSION — LGPL-2.1-or-later (LGPL-2.1.txt). Исходники: $(jqr '.openconnect.source' "$MANIFEST")
  Изменение: compat.c — заголовок sec_api/stdlib_s.h заменён на stdlib.h.
GnuTLS, libiconv, libintl (gettext), libtasn1 — LGPL-2.1-or-later (LGPL-2.1.txt).
GMP, Nettle, libidn2 — LGPL-3.0-or-later или GPL-2.0-or-later, распространяются по LGPL-3.0 (LGPL-3.0.txt, GPL-3.0.txt).
libunistring — LGPL-3.0-or-later или GPL-3.0-or-later, распространяется по LGPL-3.0.
lz4 (библиотека) — BSD-2-Clause, Copyright (c) Yann Collet.
p11-kit — BSD-3-Clause (p11-kit-COPYING.txt). zstd — BSD-3-Clause. zlib — Zlib. libxml2, libffi, brotli — MIT.
winpthreads — MIT и BSD-3-Clause-Clear. Wintun $WINTUN_VERSION — Prebuilt Binaries License (wintun-LICENSE.txt).

Библиотеки подключаются динамически и лежат рядом с SplitVpn.OpenConnect.exe открытыми файлами: их можно
заменить собственной сборкой той же версии программного интерфейса. Исходники пакетов MSYS2 —
https://github.com/msys2/MINGW-packages (каталоги mingw-w64-<имя>) и https://repo.msys2.org/mingw/sources/.
По запросу исходники всех перечисленных LGPL-компонентов в использованных версиях предоставляются бесплатно.
EOF

(cd "$OUT" && sha256sum *.dll > SHA256SUMS.txt)
echo "== готово: $(ls "$OUT"/*.dll | wc -l) DLL"
cat "$OUT/SHA256SUMS.txt"
