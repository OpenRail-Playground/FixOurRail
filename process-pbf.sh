#!/usr/bin/env bash

# Requires https://osmcode.org/osmium-tool/
osmium tags-filter $1 -F pbf w/railway=rail -f xml \
    | node src/findings.js \
