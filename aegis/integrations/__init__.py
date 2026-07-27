"""Framework integrations and workload simulation."""
from .simulated_agent import WorkloadItem, attack_item, benign_item, make_workload

__all__ = ["make_workload", "WorkloadItem", "benign_item", "attack_item"]


def run_langgraph_demo():
    # imported lazily so the core package does not hard-depend on langgraph
    from .langgraph_adapter import run_demo
    return run_demo()
