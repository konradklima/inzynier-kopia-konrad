#!/bin/zsh
# Dwuklik uruchamia panel i otwiera przeglądarkę.
cd "$(dirname "$0")"
if [ -x .venv/bin/python ]; then
  exec .venv/bin/python run.py
fi
exec python3 run.py
