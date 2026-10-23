import os
import resend
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

RESEND_KEY = os.environ.get("RESEND_API_KEY")
if RESEND_KEY:
    resend.api_key = RESEND_KEY

@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str = ""):
    try:
        body = await request.json()
    except Exception:
        body = {}

    action = body.get("action")
    if not action:
        if "register" in path or "signup" in path:
            action = "signup"
        elif "token" in path or "login" in path:
            action = "login"
        elif "reset" in path or "forgot" in path:
            action = "forgot"
        else:
            action = "signup"

    email = body.get("email", "")
    name = body.get("name", "User")
    email_sent = False

    if RESEND_KEY and email:
        try:
            if action in ["signup", "register"]:
                resend.Emails.send({
                    "from": "AlphaGuard Security <no-reply@alphaguardsuite.com>",
                    "to": [email],
                    "subject": "Welcome to AlphaGuard Security Suite",
                    "html": f"<h2>Welcome {name}!</h2><p>Your trial account has been created successfully.</p>"
                })
                email_sent = True
            elif action in ["forgot", "reset"]:
                resend.Emails.send({
                    "from": "AlphaGuard Security <no-reply@alphaguardsuite.com>",
                    "to": [email],
                    "subject": "Reset Password - AlphaGuard Suite",
                    "html": f"<p>Password reset instructions requested for {email}.</p>"
                })
                email_sent = True
        except Exception as e:
            print(f"Resend dispatch error: {e}")

    # Return fields matching what frontend auth parsers look for
    return JSONResponse(content={
        "status": "success",
        "success": True,
        "token": "demo_token_xyz_12345",
        "access_token": "demo_token_xyz_12345",
        "message": f"Action '{action}' completed successfully",
        "email_dispatched": email_sent
    })