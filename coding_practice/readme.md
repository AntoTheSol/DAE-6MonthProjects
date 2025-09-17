

# Create a new branch
git checkout -b feature/demo

# To revert to the main branch 
git checkout main

# Show what branch im on
git branch

# Will start working in the feature/demo branch
git branch feature/demo

echo "# Change" >> linked_list.py
cat linked_list.py

# This will stash a change with a commit message
git stash push -m "this is a temporary change" 

# Will stash both tracked and untracked files
git stash -u

# Will take change you made in the stash and 
git stash pop



#
git rebase -i HEAD~n

