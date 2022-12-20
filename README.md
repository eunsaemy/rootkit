# rootkit

## COMP 8505 - Final Project

To create a rootkit with a command and control system.

The attacker menu must at least allow for:
- Start the key logger
- Stop the key logger
- Transfer a file from the victim to the attacker
- Start watching a file for changes and when the file changes, transfer it to the attacker
- Stop watching a file for changes
- Start watching a directory for changes and when a file is created or modified in the directory, transfer it to the attacker
- Stop watching a directory
- Version any files that are transferred
- Store transferred files in directories by victim IP
- Shell script

The victim process must disguise its name so that it cannot be detected with "ps alx"

### To run attacker.py:

```python attacker.py```

### To run victim.py:

```python victim.py```
