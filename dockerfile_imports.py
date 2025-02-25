#!/usr/bin/env python3
"""
Import correction file for Docker environment
This ensures all necessary modules are available
"""
import os
import sys
import re
import pandas as pd
import numpy as np
import joblib
import traceback
from scipy.sparse import issparse
from pymongo import MongoClient

print("Import verification complete - all modules available")