import json
import functools

class PredictionCache:
    def __init__(self, maxsize=1000):
        self.cache = {}
        self.maxsize = maxsize
        self.keys = []

    def get(self, data):
        key = json.dumps(data, sort_keys=True)
        if key in self.cache:
            return self.cache[key]
        return None

    def set(self, data, result):
        key = json.dumps(data, sort_keys=True)
        if key not in self.cache:
            if len(self.keys) >= self.maxsize:
                oldest = self.keys.pop(0)
                del self.cache[oldest]
            self.keys.append(key)
        self.cache[key] = result
        
prediction_cache = PredictionCache()
