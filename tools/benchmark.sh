#!/bin/sh
# Run from the repository root. Outputs are intentionally gitignored.
set -eu
mkdir -p .local/benchmarks
docker compose build device gateway cloud benchmark
docker compose run --rm --no-deps benchmark "$@" > .local/benchmarks/crypto.json
docker image inspect mlkem-modernize-device mlkem-modernize-gateway mlkem-modernize-cloud \
  --format '{{json .RepoTags}} {{.Size}} bytes' > .local/benchmarks/images.txt
printf 'Results: .local/benchmarks/crypto.json and .local/benchmarks/images.txt\n'
