#!/usr/bin/env python3
"""
Standalone entropy module to avoid import errors
This file provides the entropy function directly
"""
import numpy as np

def entropy(pk, qk=None, base=None):
    """Calculate entropy from probability distribution."""
    pk = np.asarray(pk)
    pk = pk / float(np.sum(pk))
    if base is None:
        base = np.e
        
    vec = pk * np.log(pk)
    vec[~np.isfinite(vec)] = 0.0  # Handle zeros properly
    return -np.sum(vec)
