#!/bin/bash
# Thin wrapper kept for the README; see the Makefile for individual targets.
set -e
cd "$(dirname "$0")"
command -v fyne >/dev/null 2>&1 || make tools
exec make dist
