import base64, json, os, time, uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOKEN_TTL_SECONDS = 60

def _private_key():
    raw=os.getenv("SENTINEL_SIGNING_PRIVATE_KEY_B64", "")
    if not raw:
        raise RuntimeError("SENTINEL_SIGNING_PRIVATE_KEY_B64 is not configured")
    pem=base64.b64decode(raw, validate=True)
    key=serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Execution signing key must be Ed25519")
    return key

def sign_execution_authorization(*, job_id, proposal, approval, scope_revision_id, execution_id):
    now=int(time.time())
    claims={
        "iss":"sentinel-backend", "aud":"sentinel-scanner", "jti":str(uuid.uuid4()),
        "iat":now, "exp":now+TOKEN_TTL_SECONDS, "job_id":job_id,
        "proposal_id":proposal.id, "proposal_version":proposal.version,
        "approval_id":approval.id, "project_id":proposal.project_id,
        "transcript_id":proposal.transcript_id, "scope_revision_id":scope_revision_id,
        "execution_id":execution_id, "tool":proposal.tool, "action":proposal.action,
        "target":proposal.target, "parameters":proposal.parameters,
    }
    body=json.dumps(claims, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()
    signature=_private_key().sign(body)
    enc=lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return enc(body)+"."+enc(signature)
