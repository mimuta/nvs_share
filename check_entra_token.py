#!/usr/bin/env python3
"""Check an Entra token's shape before wiring AgentCore Gateway + Databricks federation.

Decodes only, no signature check. Tells you the issuer string the Databricks federation
policy needs, which subject_claim to use, and whether one aud satisfies both validators.

  python3 check_entra_token.py <token> [--expect-audience <aud you configured>]
"""
import base64, json, sys

def seg(s):
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    tok, argv = sys.argv[1], sys.argv
    expect = argv[argv.index("--expect-audience") + 1] if "--expect-audience" in argv else None
    parts = tok.strip().split(".")
    if len(parts) < 2:
        sys.exit("Not a JWT: expected at least two dot-separated segments.")
    c = seg(parts[1])
    iss, aud = c.get("iss", ""), c.get("aud")
    if isinstance(aud, list) and len(aud) == 1:
        aud = aud[0]

    if "sts.windows.net" in iss:
        ver, policy_iss = "v1.0", iss if iss.endswith("/") else iss + "/"
    elif iss.endswith("/v2.0"):
        ver, policy_iss = "v2.0", iss
    elif "cognito-idp" in iss:
        ver, policy_iss = "not Entra (Amazon Cognito test IdP)", iss
    else:
        ver, policy_iss = "UNRECOGNISED, confirm which endpoint minted it", iss

    print(f"iss   : {iss}\naud   : {aud}\nver   : {ver}")
    print(f"policy issuer -> {policy_iss}")
    print(f"discoveryUrl  -> {policy_iss.rstrip('/')}/.well-known/openid-configuration\n")

    bad, note = [], []
    if isinstance(aud, list):
        bad.append(f"aud is a list {aud}. One value must satisfy both validators.")
    elif not aud:
        bad.append("No aud claim. The Gateway authorizer validates aud, so this cannot work.")
    elif any(r in str(aud) for r in ("windows.net", "graph.microsoft.com", "sharepoint")):
        bad.append(f"aud '{aud}' is another Microsoft resource, not your agent's own app. "
                   "Register an app for the agent and request a token scoped to it.")
    if expect and str(aud) != str(expect):
        bad.append(f"aud '{aud}' does not match your configured '{expect}'. Gateway "
                   "allowedAudience and the Databricks policy must both name the real aud.")

    claim = next((k for k in ("email", "preferred_username", "upn") if c.get(k)), None)
    if claim:
        note.append(f"Use subject_claim '{claim}'. It carries '{c[claim]}', which must exist "
                    "as a Databricks user." + (" 'upn' is common on v1.0 tokens."
                    if claim == "upn" else ""))
    else:
        bad.append("None of 'email', 'preferred_username' or 'upn' is present. subject_claim "
                   "must name a claim that exists AND resolves to a Databricks user.")

    if ver == "v1.0":
        note.append("v1.0 token. A scope ending in /.default returns this even from the v2.0 endpoint.")
    if "client_id" not in c:
        note.append("No client_id claim, expected for Entra. Use allowedAudience, not allowedClients.")

    for b in bad:
        print(f"  [PROBLEM] {b}")
    for n in note:
        print(f"  [note]    {n}")
    if not bad:
        print("  No shape problems found.")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
