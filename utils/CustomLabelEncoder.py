from sklearn.preprocessing import LabelEncoder

class CustomLabelEncoder:
    def __init__(self):
        self.encoder = LabelEncoder()
        self.classes_ = []

    def fit(self, data):
        self.encoder.fit(data)
        self.classes_ = list(self.encoder.classes_)

    def transform(self, data):
        new_classes = set(data) - set(self.classes_)
        if new_classes:
            self.classes_.extend(new_classes)
            self.encoder.fit(self.classes_)
        return self.encoder.transform(
            [self.classes_[self.classes_.index(x)] if x in self.classes_ else 'UNKNOWN' for x in data])