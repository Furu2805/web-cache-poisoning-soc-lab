"""Dataset + offline model pipeline. Online evaluation follows a service restart."""
from traffic.collect import collect
from ml.train import train
from ml.evaluate import evaluate

if __name__=="__main__":
    collect()
    train()
    evaluate()
    print("NEXT: docker compose restart detector")
    print("THEN: docker compose run --rm runner python -m traffic.experiments")
    print("THEN: docker compose run --rm runner python -m traffic.benchmark")
