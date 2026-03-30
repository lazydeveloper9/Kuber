import time
import uuid
import os

from agent import (
    k8s_agent,
    default_state,
    get_pending_hitl_interrupt,
    resume_cycle,
    wait_for_hitl_decision,
)

HITL_TIMEOUT_SECONDS = 300
HITL_POLL_SECONDS = 5
AUTO_REJECT_ON_TIMEOUT = os.getenv("K8SWHISPERER_AUTO_REJECT_ON_TIMEOUT", "true").strip().lower() in {"1", "true", "yes"}


def run_cycle_with_langgraph() -> None:
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}

    print(f"🧠 Running LangGraph cycle (thread_id={thread_id})")
    k8s_agent.invoke(default_state(), config=config)

    # If interrupted for HITL, poll decision and resume from checkpoint.
    interrupt_info = get_pending_hitl_interrupt(thread_id)
    while interrupt_info:
        request_id = interrupt_info.get("request_id")
        print("🛑 HITL interrupt raised by Safety Gate.")

        approved = None
        if request_id:
            print(f"📨 Waiting for approval on request_id={request_id}...")
            approved = wait_for_hitl_decision(
                request_id,
                timeout_seconds=HITL_TIMEOUT_SECONDS,
                poll_seconds=HITL_POLL_SECONDS,
            )

        if approved is None:
            if AUTO_REJECT_ON_TIMEOUT:
                print("⏱️ No HITL decision received in time. Auto-rejecting for safety.")
                approved = False
            else:
                choice = input("Approve this action? (y/n): ").strip().lower()
                approved = choice == "y"

        print(f"🔁 Resuming graph with approved={approved}")
        resume_cycle(thread_id, approved)
        interrupt_info = get_pending_hitl_interrupt(thread_id)


def main() -> None:
    print("🚀 Starting K8sWhisperer Autonomous Agent (LangGraph + MemorySaver)...\n")
    try:
        while True:
            print("\n" + "=" * 50)
            print("⏳ INITIATING 30-SECOND CLUSTER SCAN...")
            print("=" * 50)

            run_cycle_with_langgraph()

            print("\n⏲️ Scan complete. Sleeping for 30 seconds... (Press Ctrl+C to exit)")
            time.sleep(30)

    except KeyboardInterrupt:
        print("\n🛑 Shutting down K8sWhisperer agent. Goodbye!")


if __name__ == "__main__":
    main()
