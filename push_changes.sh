#!/bin/bash
cd /Users/attripathi/MemoryTool
echo "Current directory: $(pwd)"
echo "Git status:"
git status
echo "Adding files..."
git add .
echo "Committing..."
git commit -m "Fix MinGW compilation errors - std::min namespace and remove threading"
echo "Pushing to GitHub..."
git push origin main
echo "Done!"