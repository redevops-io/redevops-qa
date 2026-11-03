#!/bin/bash
cd "$(dirname "$0")"
PYTHONPATH=$PWD python3 -s -m qa_runner.netfence --probe
