import cProfile
import pstats
import io
import time
from app import create_app
from models.model_manager import ModelManager

def run_performance_test():
    app = create_app()
    with app.app_context():
        mm = ModelManager()
        mm._load_models_with_context(app)
        
        data = {"model_type": "traffic", "features": [1000.0, 15.0, 1.0, 0]}
        
        start = time.time()
        for i in range(100):
            mm.predict(data)
        end = time.time()
        print(f"Time for 100 predictions: {end - start:.4f} seconds")

if __name__ == "__main__":
    pr = cProfile.Profile()
    pr.enable()
    run_performance_test()
    pr.disable()
    s = io.StringIO()
    sortby = 'cumulative'
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats(20)
    print(s.getvalue())
