import re


class Rule:
    def __init__(self, rule_id, name, pattern, field, severity='medium', description=None, created_at=None,
                 rule_type=None):
        self.id = rule_id
        self.name = name
        self.pattern = pattern
        self.field = field
        self.severity = severity
        self.description = description
        self.created_at = created_at
        self.type = rule_type
        self._compiled_pattern = re.compile(pattern, re.IGNORECASE)

    def check(self, data):
        """Check if the rule matches the given data."""
        if self.field not in data:
            return False

        value = str(data[self.field])
        return bool(self._compiled_pattern.search(value))

    def to_dict(self):
        """Convert rule to dictionary for storage."""
        return {
            'name': self.name,
            'pattern': self.pattern,
            'field': self.field,
            'severity': self.severity,
            'description': self.description,
            'created_at': self.created_at,
            'type': self.type
        }