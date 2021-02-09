"""
Checks for instances of nosec tags in code without a reference

This indicates where the author has told Bandit to ignore a finding
but there may be an incomplete audit trail for it.

It doesn't validate the reference is correct or accurate, just
that there is a reference noted in the code.
"""
import glob


def test_for_unreferenced_nosec_tags():
    for item in glob.iglob('**', recursive=True):
        if item.endswith('.py'):
            if item.startswith('tests/'):
                continue
            with open(item, 'r') as f:
                line_number = 1
                for line in f.readlines():
                    result = not (('#nosec' in line) and ('CYBASIMP' not in line))
                    assert result, F"{item}:{line_number} #nosec but no reference"
                    line_number += 1
    

test_for_unreferenced_nosec_tags()
