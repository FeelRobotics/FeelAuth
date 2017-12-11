
class MockQuery:

    def filter_by(self, api_key=None):
        self.api_key = api_key
        return self

    def first(self):
        if self.api_key == 'VALID':
            return MockApplicationModel()
        else:
            return None

    def get(self, id):
        if id == 1:
            return MockApplicationModel()
        else:
            return None


class MockApplicationModel:
    query = MockQuery()
    id = 1

