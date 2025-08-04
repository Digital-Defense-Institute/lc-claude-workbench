#!/bin/bash
# Update Sigma LimaCharlie detection rules from upstream

echo "Updating Sigma LimaCharlie detection rules..."

# Navigate to the repository root
cd "$(dirname "$0")"

# Update the submodule to latest commit from rules branch
git submodule update --remote --merge references/sigma-limacharlie

echo "Sigma rules updated successfully!"
echo "Latest rules are now available in: references/sigma-limacharlie/"
echo ""
echo "To commit the update to your repository, run:"
echo "  git add references/sigma-limacharlie"
echo "  git commit -m 'Update Sigma LimaCharlie rules to latest version'"