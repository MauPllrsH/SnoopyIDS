#!/usr/bin/env python3
"""
Simple fix for SnoopyIDS - modifies Dockerfile to explicitly install scipy
"""
import os
import re

def main():
    print("Fixing SnoopyIDS Docker setup...")
    
    # Check Dockerfile
    dockerfile_path = "Dockerfile"
    
    with open(dockerfile_path, 'r') as f:
        content = f.read()
    
    # Check if scipy is already included
    if 'pip install' in content and 'scipy' not in content:
        # Add scipy to pip install
        updated_content = re.sub(
            r'(pip install .*?requirements\.txt)',
            r'\1 scipy',
            content
        )
        
        # Write back the updated Dockerfile
        with open(dockerfile_path, 'w') as f:
            f.write(updated_content)
        
        print("✅ Added scipy to Dockerfile")
    else:
        print("✅ Dockerfile already includes scipy")
    
    print("\nFix complete!")
    print("To apply these changes, run:")
    print("  docker-compose down")
    print("  docker-compose build --no-cache")
    print("  docker-compose up -d")

if __name__ == "__main__":
    main()