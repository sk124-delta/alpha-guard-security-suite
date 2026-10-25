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
        sender = "no-reply@alphaguardsuite.com"
        resend.Emails.send({
            "from": f"AlphaGuard Security <{sender}>",
            "to": [data.email],
            "subject": "Reset Password - AlphaGuard Suite",
            "html": f"""
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Password Reset Request</h2>
                    <p>We received a request to reset your password for AlphaGuard Suite.</p>
                    <p>Click the link below to set your new password:</p>
                    <a href="https://www.alphaguardsuite.com/update-password.html?email={data.email}"
                       style="background: #06b6d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                       Reset Password
                    </a>
                    <p style="margin-top: 20px; color: #666; font-size: 12px;">If you didn't request this, you can safely ignore this email.</p>
                </div>
            """
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))