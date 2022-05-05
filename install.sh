#!/bin/bash

set -e
set -x

# gcc libffi-dev
sudo apt-get install python3-pip virtualenv -y

if [ -z "$VIRTUAL_ENV" ]; then
    virtualenv -p python3 venv
    . ./venv/bin/activate
fi

python3 -m pip install -r requirement.txt
