import base64, json, os, sqlite3, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException

DB_PATH=os.getenv("SCANNER_REPLAY_DB","/var/lib/sentinel/results/used_authorizations.sqlite3")

def _public_key():
    raw=os.getenv("SENTINEL_SIGNING_PUBLIC_KEY_B64","")
    if not raw: raise RuntimeError("SENTINEL_SIGNING_PUBLIC_KEY_B64 is not configured")
    key=serialization.load_pem_public_key(base64.b64decode(raw,validate=True))
    if not isinstance(key,Ed25519PublicKey): raise RuntimeError("Execution verification key must be Ed25519")
    return key

def verify_and_consume(token: str, job: dict) -> dict:
    if not token or token.count(".")!=1:
        raise HTTPException(status_code=401,detail="Missing or malformed execution authorization")
    decode=lambda s: base64.urlsafe_b64decode(s+"="*((4-len(s)%4)%4))
    body_part,sig_part=token.split(".")
    try:
        body=decode(body_part); signature=decode(sig_part)
        _public_key().verify(signature,body)
        claims=json.loads(body)
        if not isinstance(claims, dict):
            raise ValueError("Authorization claims must be a JSON object")
        if not isinstance(claims, dict):
            raise ValueError("Authorization claims must be a JSON object")
    except Exception as exc:
        raise HTTPException(status_code=401,detail="Invalid execution authorization signature") from exc
    now=int(time.time())
    if claims.get("iss")!="sentinel-backend" or claims.get("aud")!="sentinel-scanner":
        raise HTTPException(status_code=403,detail="Execution authorization issuer/audience mismatch")
    if not isinstance(claims.get("iat"),int) or not isinstance(claims.get("exp"),int) or claims["iat"]>now+5 or claims["exp"]<=now or claims["exp"]-claims["iat"]>60:
        raise HTTPException(status_code=401,detail="Execution authorization expired or has invalid lifetime")
    expected={"job_id":job.get("job_id"),"tool":job.get("tool"),"action":job.get("action"),
              "target":job.get("target"),"parameters":job.get("parameters",{})}
    for key,value in expected.items():
        if claims.get(key)!=value:
            raise HTTPException(status_code=403,detail=f"Execution authorization does not match job ({key})")
    required=("jti","proposal_id","approval_id","project_id","transcript_id","scope_revision_id","execution_id")
    if any(not isinstance(claims.get(k),str) or not claims[k] for k in required):
        raise HTTPException(status_code=401,detail="Execution authorization is incomplete")
    Path(DB_PATH).parent.mkdir(parents=True,exist_ok=True)
    try:
        with sqlite3.connect(DB_PATH,timeout=10,isolation_level="IMMEDIATE") as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS consumed_authorizations (jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)")
            conn.execute("DELETE FROM consumed_authorizations WHERE expires_at <= ?",(now,))
            conn.execute("INSERT INTO consumed_authorizations(jti,expires_at) VALUES (?,?)",(claims["jti"],claims["exp"]))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409,detail="Execution authorization has already been used") from exc
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503,detail="Replay-protection store unavailable") from exc
    return claims
