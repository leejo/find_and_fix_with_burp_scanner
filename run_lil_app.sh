#!/bin/bash

app=$1

MOJO_MODE=production morbo -l https://127.0.0.1:3000 -v $app
