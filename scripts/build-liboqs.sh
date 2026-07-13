#!/bin/sh
set -eu

VERSION="0.16.0"
ARCHIVE_SHA256="162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae"
OUTPUT="${1:-.local/oqs}"

if [ -f "$OUTPUT/lib/liboqs.so.$VERSION" ]; then
  printf '%s\n' "liboqs $VERSION already installed at $OUTPUT"
  exit 0
fi
if [ -e "$OUTPUT" ]; then
  printf '%s\n' "refusing to replace non-matching path: $OUTPUT" >&2
  exit 2
fi

for command in cmake curl sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "missing build dependency: $command" >&2
    exit 2
  }
done

WORK=$(mktemp -d)
STAGE="$OUTPUT.stage.$$"
cleanup() {
  rm -rf "$WORK" "$STAGE"
}
trap cleanup EXIT INT TERM

curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VERSION.tar.gz" \
  --output "$WORK/liboqs.tar.gz"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$WORK/liboqs.tar.gz" | sha256sum --check --status
tar -xzf "$WORK/liboqs.tar.gz" -C "$WORK"

cmake -S "$WORK/liboqs-$VERSION" -B "$WORK/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$STAGE" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_DIST_BUILD=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_MINIMAL_BUILD='KEM_ml_kem_768;SIG_ml_dsa_65'
cmake --build "$WORK/build" --parallel "${BUILD_JOBS:-2}"
cmake --install "$WORK/build"
mkdir -p "$(dirname "$OUTPUT")"
mv "$STAGE" "$OUTPUT"
printf '%s\n' "installed liboqs $VERSION with ML-KEM-768 and ML-DSA-65 at $OUTPUT"
