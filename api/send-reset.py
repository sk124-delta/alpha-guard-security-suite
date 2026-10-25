import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import resend

app = FastAPI()

class ResetRequest(BaseModel):
    email: str

resend.api_key = os.environ.get("RESEND_API_KEY")

@app.post("/api/send-reset")
async def send_reset(data: ResetRequest):
    try:
        sender = "onboarding@resend.dev"
        resend.Emails.send({
            "from": f"AlphaGuard Security <{sender}>",
            "to": [data.email],
            "subject": "Reset Password - AlphaGuard Suite",
            "html": f"<p>Password reset instructions requested for {data.email}.</p>"
        })
        return {"status": "success", "success": True, "message": "Email dispatched successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))