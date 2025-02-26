#!/bin/bash
# Start SnoopyIDS with preloaded modules
python -u preload.py
python -u preload.py && python -u preload.py && python -u app.py
