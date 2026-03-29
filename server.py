import json
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from agent import k8s_agent

app = FastAPI(title="K8sWhisperer Webhook")

def resume_langgraph_thread(thread_id: str, is_approved: bool):
    """Background task to resume the LangGraph execution."""
    print(f">>> [HITL] Resuming thread {thread_id} | Approved: {is_approved}")
    
    config = {"configurable": {"thread_id": thread_id}}
    
    # 1. Update the state with the human's decision.
    # We update it as if the 'hitl_interrupt' node produced this state change.
    k8s_agent.update_state(
        config, 
        {"approved": is_approved}, 
        as_node="hitl_interrupt"
    )
    
    # 2. Invoke the graph with no new input to resume from the interrupt point.
    k8s_agent.invoke(None, config)

@app.post("/slack/interactive")
async def slack_interactive_webhook(request: Request, background_tasks: BackgroundTasks):
    """Catches Block Kit button clicks from Slack."""
    # Slack sends URL-encoded form data with a 'payload' field containing JSON
    form_data = await request.form()
    payload_str = form_data.get("payload")
    
    if not payload_str:
        return JSONResponse(content={"error": "No payload"}, status_code=400)
        
    payload = json.loads(payload_str)
    
    # We only care about block_actions (button clicks)
    if payload.get("type") == "block_actions":
        action = payload["actions"][0]
        action_id = action.get("action_id")
        
        # We embed the LangGraph thread_id in the button's value field when we send the Slack message
        thread_id = action.get("value") 
        
        is_approved = (action_id == "approve_action")
        
        # Hand the resumption off to a background task so Slack gets an immediate 200 OK
        background_tasks.add_task(resume_langgraph_thread, thread_id, is_approved)
        
        # Optional: You can return a Block Kit message here to update the original Slack message
        # e.g., changing the buttons to text saying "Approved by @user"
        return JSONResponse(content={"text": f"Action {'approved' if is_approved else 'rejected'}."})

    return JSONResponse(content={"status": "ignored"})