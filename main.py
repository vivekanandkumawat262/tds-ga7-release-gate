from fastapi import FastAPI
from typing import Any

app = FastAPI()


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # --------------------------------------------------
    # 1. Permissions must be EXACTLY least privilege
    # --------------------------------------------------
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    permissions = workflow.get("permissions", {})

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # --------------------------------------------------
    # 2. Pull request must use pull_request
    # --------------------------------------------------
    event = payload.get("event")
    trigger = workflow.get("trigger")

    if event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # --------------------------------------------------
    # 3. Tests must pass, matrix complete,
    #    failFast must be false
    # --------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # --------------------------------------------------
    # 4. Action pinning
    # --------------------------------------------------
    actions = workflow.get("actions", [])

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref", "")

        # Official actions/* may use tags
        if owner == "actions":
            continue

        # Third-party actions require exactly
        # 40 lowercase hexadecimal characters
        if (
            len(ref) != 40
            or any(c not in "0123456789abcdef" for c in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # --------------------------------------------------
    # 5. Image must be multi-stage
    # --------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # --------------------------------------------------
    # 6. Container must not run as root
    # --------------------------------------------------
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # --------------------------------------------------
    # 7. Secret handling
    # --------------------------------------------------
    secret_mode = image.get("secretMode")

    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # --------------------------------------------------
    # 8. Critical vulnerabilities must be zero
    # --------------------------------------------------
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # --------------------------------------------------
    # 9. Image must be digest pinned
    # --------------------------------------------------
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # --------------------------------------------------
    # 10. Production requirements
    # --------------------------------------------------
    if payload.get("target") == "production":

        if (
            event != "push"
            or payload.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # --------------------------------------------------
    # Final decision
    # --------------------------------------------------
    decision = "promote" if not violations else "block"

    return {
        "decision": decision,
        "violations": violations,
    }