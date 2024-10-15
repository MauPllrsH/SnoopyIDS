import re


class Rule:
    def __init__(self, name, pattern, field):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.field = field

    def check(self, data):
        if self.field in data:
            return self.pattern.search(data[self.field])
        return False