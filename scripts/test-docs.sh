#!/usr/bin/env bash

set -x

set -e

echo "Building docs with Sphinx"
rm -rf docs/_build
make -C docs html

echo "Checking links with Sphinx"
rm -rf docs/_build
make -C docs linkcheck

echo "Checking grammar and style"
write-good docs/*.rst --weasel --so --passive --illusion --thereIs --toowordy --adverb --cliches
