from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import requests
import random
import os
from dotenv import load_dotenv
import urllib.parse

load_dotenv()

AUTHKEY = os.getenv("AUTHKEY")
COUNTRY_CODE = os.getenv("COUNTRY_CODE", "91")
SID = os.getenv("SID")

app = FastAPI()

# Temporary in-memory storage (use Redis in production)
logid_store = {}
otp_store = {}


class RegisterRequest(BaseModel):
    full_name: str
    email: EmailStr
    phone: str


class OTPVerifyRequest(BaseModel):
    phone: str
    otp: str


# -------------------- OTP Sender -------------------- #

def send_otp_via_authkey(phone: str, otp: str):
    if not SID:
        raise HTTPException(status_code=500, detail="2FA Template SID not configured")

    # Use the public API endpoint that worked in your manual test and pass the OTP explicitly
    url = (
        f"https://api.authkey.io/request?"
        f"authkey={AUTHKEY}"
        f"&mobile={phone}"
        f"&country_code={COUNTRY_CODE}"
        f"&sid={SID}"
        f"&otp={otp}"
    )

    response = requests.get(url)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Failed to send OTP: {response.status_code}")

    try:
        result = response.json()
        if "LogID" not in result:
            # Some endpoints may return non-JSON or different shape; include raw text for debugging
            raise HTTPException(status_code=500, detail=f"Invalid response from AuthKey: {response.text}")
        return result
    except ValueError:
        raise HTTPException(status_code=500, detail=f"Invalid JSON response from AuthKey: {response.text}")


# -------------------- Routes -------------------- #

@app.post("/register")
async def register_user(data: RegisterRequest):
    # Generate OTP and send via AuthKey 2FA API
    otp = str(random.randint(100000, 999999))
    otp_store[data.phone] = otp

    result = send_otp_via_authkey(data.phone, otp)

    # store LogID for server-side verification fallback
    logid_store[data.phone] = result["LogID"]

    return {
        "message": "OTP sent successfully",
        "phone": data.phone,
        "api_response": result
    }


@app.post("/verify-otp")
async def verify_otp(data: OTPVerifyRequest):
    # First try local OTP store (fast, offline)
    local_otp = otp_store.get(data.phone)
    if local_otp:
        if local_otp == data.otp:
            del otp_store[data.phone]
            # also remove any stored logid
            logid_store.pop(data.phone, None)
            return {"message": "OTP verified successfully!"}
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP")

    # Fallback to server-side verification using LogID
    logid = logid_store.get(data.phone)
    if not logid:
        raise HTTPException(status_code=400, detail="No OTP request found for this phone")

    url = (
        f"https://console.authkey.io/api/2fa_verify.php?"
        f"authkey={AUTHKEY}"
        f"&channel=SMS"
        f"&otp={data.otp}"
        f"&logid={logid}"
    )

    response = requests.get(url)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to verify OTP")

    try:
        result = response.json()
        if result.get("status") == True:
            # OTP verified → clean up
            del logid_store[data.phone]
            return {"message": "OTP verified successfully!"}
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP")
    except ValueError:
        raise HTTPException(status_code=500, detail="Invalid response from AuthKey")


@app.get("/")
async def root():
    return {"message": "FastAPI + AuthKey OTP Service running"}
