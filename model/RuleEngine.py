from model.Rule import Rule


class RuleEngine:
    def __init__(self):
        self.rules = []

    def load_rules(self, filename):
        with open(filename, 'r') as file:
            for line in file:
                name, pattern, field = line.strip().split('|')
                self.rules.append(Rule(name, pattern, field))

    def check_rules(self, data):
        for rule in self.rules:
            if rule.check(data):
                return rule.name
        return None
