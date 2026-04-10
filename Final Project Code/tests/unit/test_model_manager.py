import pytest
from models.model_manager import ModelManager
from utils.cache import prediction_cache

def test_prediction_cache():
    prediction_cache.cache.clear()
    mm = ModelManager()
    
    data = {"model_type": "traffic", "features": [100.0, 10.0, 1.0, 0]}
    
    # First call
    res1 = mm.predict(data)
    assert res1['prediction'] in ["Malicious", "Normal"]
    
    # Second call should be cached (we can test by modifying cache manually or checking if we hit branch)
    # Since we can't easily spy without pytest-mock, let's just make sure it returns the same result
    prediction_cache.cache[list(prediction_cache.cache.keys())[0]] = {"prediction": "Cached Result"}
    
    res2 = mm.predict(data)
    assert res2['prediction'] == "Cached Result"
