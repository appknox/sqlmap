# Tired of using next in replacement of max and min
def max_none(a, b):
    if a is None:
        a = float('-inf')
    if b is None:
        b = float('-inf')
    return max(a, b)


def min_none(a, b):
    if a is None:
        a = float('inf')
    if b is None:
        b = float('inf')
    return min(a, b)
