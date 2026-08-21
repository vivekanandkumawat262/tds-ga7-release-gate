from fastapi import FastAPI, Body
from typing import Any
import re
import html
from urllib.parse import unquote, urlparse

app = FastAPI()


# Your assigned scope
ASSIGNED_TENANT = "tenant-mkc2fyf"
ALLOWED_EMAIL_DOMAIN = "notify-v6i11cb.example"


@app.post("/sanitize-output")
def sanitize_output(payload: Any = Body(...)):
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




# ============================================================
# Question 2: /action-firewall
# ============================================================

def valid_string(value):
    return isinstance(value, str)


def exact_keys(obj, required_keys):
    return (
        isinstance(obj, dict)
        and set(obj.keys()) == set(required_keys)
    )


def valid_top_level(payload):
    if not isinstance(payload, dict):
        return False

    allowed_keys = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    # untrustedContent is optional
    if set(payload.keys()) - allowed_keys:
        return False

    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(payload.keys()):
        return False

    if payload["provenance"] not in ("trusted", "untrusted"):
        return False

    if not isinstance(payload["humanApproved"], bool):
        return False

    if "untrustedContent" in payload:
        if not isinstance(payload["untrustedContent"], str):
            return False

    action = payload["action"]

    if not isinstance(action, dict):
        return False

    if set(action.keys()) != {"tool", "args"}:
        return False

    if not isinstance(action["tool"], str):
        return False

    if not isinstance(action["args"], dict):
        return False

    return True


def valid_search_args(args):
    if not exact_keys(args, {"query"}):
        return False

    query = args["query"]

    if not isinstance(query, str):
        return False

    if not (1 <= len(query) <= 200):
        return False

    return True


def valid_lookup_args(args):
    if not exact_keys(args, {"tenantId", "recordId"}):
        return False

    if not isinstance(args["tenantId"], str):
        return False

    if not isinstance(args["recordId"], str):
        return False

    if args["recordId"] == "":
        return False

    return True


def valid_email_args(args):
    if not exact_keys(args, {"to", "subject", "body"}):
        return False

    if not isinstance(args["to"], str):
        return False

    if not isinstance(args["subject"], str):
        return False

    if not isinstance(args["body"], str):
        return False

    return True


def valid_html_args(args):
    if not exact_keys(args, {"html"}):
        return False

    if not isinstance(args["html"], str):
        return False

    return True


def unsafe_html(html):
    # Block script elements
    if re.search(r"<\s*script\b", html, re.IGNORECASE):
        return True

    # Block iframe elements
    if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
        return True

    # Block inline event handlers such as:
    # onclick=, onload=, onerror=, onmouseover=, etc.
    if re.search(r"\bon[a-zA-Z]+\s*=", html, re.IGNORECASE):
        return True

    # Block javascript: URLs
    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return True

    return False


@app.post("/action-firewall")
def action_firewall(payload: dict[str, Any]):

    # --------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # --------------------------------------------------------
    if not valid_top_level(payload):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    action = payload["action"]
    tool = action["tool"]
    args = action["args"]

    # --------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # --------------------------------------------------------
    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html",
    }

    if tool not in allowed_tools:
        return {
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED"
        }

    # --------------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # --------------------------------------------------------
    if tool == "search":
        if not valid_search_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "lookup_record":
        if not valid_lookup_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "send_email":
        if not valid_email_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "render_html":
        if not valid_html_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    # --------------------------------------------------------
    # 4. TENANT SCOPE
    # --------------------------------------------------------
    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return {
                "decision": "block",
                "reason": "TENANT_SCOPE"
            }

    # --------------------------------------------------------
    # 5. EXACT EMAIL DOMAIN
    # --------------------------------------------------------
    if tool == "send_email":

        recipient = args["to"]

        # Exactly one @
        if recipient.count("@") != 1:
            return {
                "decision": "block",
                "reason": "EGRESS_DENIED"
            }

        local_part, domain = recipient.rsplit("@", 1)

        if not local_part or domain != ALLOWED_EMAIL_DOMAIN:
            return {
                "decision": "block",
                "reason": "EGRESS_DENIED"
            }

    # --------------------------------------------------------
    # 6. HUMAN APPROVAL
    # --------------------------------------------------------
    if tool == "send_email":
        if payload["humanApproved"] is not True:
            return {
                "decision": "block",
                "reason": "APPROVAL_REQUIRED"
            }

    # --------------------------------------------------------
    # 7. HTML SAFETY
    # --------------------------------------------------------
    if tool == "render_html":
        if unsafe_html(args["html"]):
            return {
                "decision": "block",
                "reason": "UNSAFE_OUTPUT"
            }

    # --------------------------------------------------------
    # ALLOW
    # --------------------------------------------------------
    return {
        "decision": "allow",
        "reason": "ALLOW"
    }



# ============================================================
# Question 3: /terraform/plan
# ============================================================

TERRAFORM_WORKSPACE = "prod-qpc0oo"

REQUIRED_LABELS = {
    "owner": "student-oszqt",
    "environment": "production",
    "cost_center": "cc-7jnf",
}


def exact_type(value, expected_type):
    """
    Strict type check.
    This prevents True from being accepted as an integer, etc.
    """
    return type(value) is expected_type


def valid_terraform_schema(payload):
    """
    Validate the required fields and their types.
    Extra fields are allowed because the question specifies
    value-type validation rather than an exact-key schema.
    """

    if type(payload) is not dict:
        return False

    # Required top-level fields
    required = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required.issubset(payload.keys()):
        return False

    # environment
    if type(payload["environment"]) is not str:
        return False

    # state
    state = payload["state"]

    if type(state) is not dict:
        return False

    if "backend" not in state or "locked" not in state:
        return False

    if type(state["backend"]) is not str:
        return False

    if type(state["locked"]) is not bool:
        return False

    # providerVersion
    if type(payload["providerVersion"]) is not str:
        return False

    # destroyApproved
    if type(payload["destroyApproved"]) is not bool:
        return False

    # resource
    resource = payload["resource"]

    if type(resource) is not dict:
        return False

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return False

    if type(resource["address"]) is not str or resource["address"] == "":
         return False

    if type(resource["type"]) is not str or resource["type"] == "":
        return False

    if type(resource["action"]) is not str:
        return False

    if resource["action"] not in {"create", "update", "delete"}:
       return False
    
    if type(resource["labels"]) is not dict:
        return False

    for key, value in resource["labels"].items():
        if type(key) is not str:
            return False

        if type(value) is not str:
            return False

    # secret: null OR string
    if resource["secret"] is not None:
        if type(resource["secret"]) is not str:
            return False

    # forceDestroy must be boolean
    if type(resource["forceDestroy"]) is not bool:
        return False

    return True

def valid_secret_reference(secret):
    """
    secret must be:
      null
      OR
      non-empty secret://... reference
    """

    if secret is None:
        return True

    if not isinstance(secret, str):
        return False

    if not secret.startswith("secret://"):
        return False

    # Must contain something after secret://
    if len(secret) <= len("secret://"):
        return False

    return True


@app.post("/terraform/plan")
def terraform_plan(payload: dict[str, Any]):

    # --------------------------------------------------------
    # 1. INVALID PLAN
    # --------------------------------------------------------
    if not valid_terraform_schema(payload):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    resource = payload["resource"]
    state = payload["state"]

    # --------------------------------------------------------
    # 2. ENVIRONMENT
    # --------------------------------------------------------
    if payload["environment"] != TERRAFORM_WORKSPACE:
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        }

    # --------------------------------------------------------
    # 3. STATE SAFETY
    # --------------------------------------------------------
    allowed_backends = {
        "gcs",
        "s3",
        "azurerm",
        "remote",
    }

    if (
        state["backend"] not in allowed_backends
        or state["locked"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        }

    # --------------------------------------------------------
    # 4. PROVIDER PINNING
    # --------------------------------------------------------
    provider = payload["providerVersion"]

    allowed_provider_versions = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }

    if provider not in allowed_provider_versions:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        }

    # --------------------------------------------------------
    # 5. REQUIRED LABELS
    # --------------------------------------------------------
    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():

        if key not in labels:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS"
            }

        if labels[key] != expected_value:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS"
            }

    # --------------------------------------------------------
    # 6. SECRET
    # --------------------------------------------------------
    if not valid_secret_reference(resource["secret"]):
        return {
            "decision": "reject",
            "reason": "PLAINTEXT_SECRET"
        }

    # --------------------------------------------------------
    # 7. DESTRUCTIVE DELETE
    # --------------------------------------------------------
    stateful_resources = {
        "storage_bucket",
        "sql_database",
        "persistent_disk",
    }

    if (
        resource["action"] == "delete"
        and resource["type"] in stateful_resources
        and payload["destroyApproved"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        }

    # --------------------------------------------------------
    # 8. FORCE DESTROY
    # --------------------------------------------------------
    if (
        resource["type"] == "storage_bucket"
        and payload["environment"] == TERRAFORM_WORKSPACE
        and resource["forceDestroy"] is True
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        }

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------
    return {
        "decision": "approve",
        "reason": "APPROVE"
    }


# ============================================================
# Question 4: LLM Output Handling Gate
# ============================================================

ALLOWED_EXTERNAL_HOSTS = {
    "cdn-mkzgavv.example",
    "app-kfmsilv.example",
}

VALID_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


def decode_once(value: str) -> str:
    """
    Decode exactly once in this order:
      1. percent escapes
      2. selected HTML entities
      3. \\uXXXX escapes
    """

    # 1. Percent escapes
    decoded = unquote(value)

    # 2. HTML entities
    # Only the entities specified by the question.
    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    decoded = re.sub(
        r"&(?:lt|gt|quot|apos|amp);",
        lambda m: entity_map[m.group(0)],
        decoded,
        flags=re.IGNORECASE,
    )

    # Numeric HTML entities: &#NN; and &#xNN;
    def decode_numeric_entity(match):
        token = match.group(0)

        try:
            if token.lower().startswith("&#x"):
                return chr(int(token[3:-1], 16))
            return chr(int(token[2:-1], 10))
        except (ValueError, OverflowError):
            return token

    decoded = re.sub(
        r"&#(?:[0-9]+|x[0-9a-fA-F]+);",
        decode_numeric_entity,
        decoded,
    )

    # 3. Decode \uXXXX
    def decode_unicode_escape(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        decode_unicode_escape,
        decoded,
    )

    return decoded


def dangerous_scheme(text: str) -> bool:
    """
    Detect:
      javascript:
      data:
      vbscript:

    with optional whitespace before colon.
    Also detect extracted URLs using schemes other than
    http/https.
    """

    # Explicit dangerous schemes anywhere in text.
    if re.search(
        r"(?i)(?:javascript|data|vbscript)\s*:",
        text,
    ):
        return True

    return False


def extract_html_urls(text: str):
    """
    Extract quoted src= and href= values.
    """

    pattern = re.compile(
        r"""(?is)\b(?:src|href)\s*=\s*(['"])(.*?)\1"""
    )

    return [match.group(2) for match in pattern.finditer(text)]


def extract_markdown_urls(text: str):
    """
    Extract the target inside ](...).
    """

    pattern = re.compile(
        r"""\]\(\s*([^)]+?)\s*\)"""
    )

    results = []

    for match in pattern.finditer(text):
        target = match.group(1).strip()

        # Markdown titles may follow the URL:
        # ](https://example.com "title")
        if target.startswith("<"):
            end = target.find(">")
            if end != -1:
                target = target[1:end]
        else:
            # Take first whitespace-separated token.
            target = target.split()[0]

        results.append(target)

    return results


def extract_urls(channel: str, text: str):
    if channel == "html":
        return extract_html_urls(text)

    if channel == "markdown":
        return extract_markdown_urls(text)

    if channel == "url":
        return [text.strip()]

    return []


def url_has_dangerous_scheme(url: str) -> bool:
    """
    Determine whether an extracted URL has a scheme other
    than http/https.

    Protocol-relative URLs are resolved as https.
    Relative references are allowed.
    """

    candidate = url.strip()

    if not candidate:
        return False

    # Protocol-relative reference: //host/path
    if candidate.startswith("//"):
        parsed = urlparse("https:" + candidate)

        # It has an effective https scheme.
        return parsed.scheme.lower() not in {"http", "https"}

    parsed = urlparse(candidate)

    # Relative URL: /local/page, page, ./foo
    if not parsed.scheme:
        return False

    return parsed.scheme.lower() not in {"http", "https"}


def url_is_external_and_disallowed(url: str) -> bool:
    """
    Only absolute URLs are subject to the external-host allowlist.

    Allowed:
      relative URLs
      exact allowed hostnames

    Not allowed:
      other absolute hosts
      protocol-relative hosts not on allowlist
    """

    candidate = url.strip()

    if not candidate:
        return False

    # Protocol-relative URL is absolute.
    if candidate.startswith("//"):
        parsed = urlparse("https:" + candidate)

        hostname = parsed.hostname

        return hostname not in ALLOWED_EXTERNAL_HOSTS

    parsed = urlparse(candidate)

    # Relative URL is fine.
    if not parsed.scheme:
        return False

    # At this point http/https should be the only safe schemes.
    if parsed.scheme.lower() not in {"http", "https"}:
        return False

    # Absolute URL: compare parsed hostname ONLY.
    hostname = parsed.hostname

    return hostname not in ALLOWED_EXTERNAL_HOSTS


def contains_script_tag(text: str) -> bool:
    """
    Opening script, iframe, object or embed tags.
    """

    return bool(
        re.search(
            r"(?is)<\s*(?:script|iframe|object|embed)\b",
            text,
        )
    )


def contains_event_handler(text: str) -> bool:
    """
    Detect HTML attributes such as:
      onclick=
      onload=
      onerror=
      onmouseover=

    The rule is an on...= attribute.
    """

    return bool(
        re.search(
            r"""(?is)\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=""",
            text,
        )
    )


def contains_sql_metachar(text: str) -> bool:
    if "'" in text:
        return True

    if '"' in text:
        return True

    if ";" in text:
        return True

    if "--" in text:
        return True

    if "/*" in text:
        return True

    if re.search(r"(?i)\bunion\b", text):
        return True

    if re.search(r"(?i)\bor\s+1\s*=\s*1\b", text):
        return True

    return False


def contains_shell_metachar(text: str) -> bool:
    # ; & | ` < >
    if re.search(r"[;&|`<>]", text):
        return True

    # $(
    if "$(" in text:
        return True

    # ${
    if "${" in text:
        return True

    return False


def trips_channel_rule(channel: str, text: str) -> bool:
    """
    Used for the encoded-payload test.

    Returns whether the decoded value would violate any
    applicable channel rule.
    """

    if channel == "html":
        if contains_script_tag(text):
            return True

        if contains_event_handler(text):
            return True

        if dangerous_scheme(text):
            return True

        for url in extract_html_urls(text):
            if url_has_dangerous_scheme(url):
                return True

            if url_is_external_and_disallowed(url):
                return True

        return False

    if channel == "markdown":
        if dangerous_scheme(text):
            return True

        for url in extract_markdown_urls(text):
            if url_has_dangerous_scheme(url):
                return True

            if url_is_external_and_disallowed(url):
                return True

        return False

    if channel == "url":
        if dangerous_scheme(text):
            return True

        url = text.strip()

        if url_has_dangerous_scheme(url):
            return True

        if url_is_external_and_disallowed(url):
            return True

        return False

    if channel == "sql":
        return contains_sql_metachar(text)

    if channel == "shell":
        return contains_shell_metachar(text)

    return False


@app.post("/sanitize-output")
def sanitize_output(payload: Any = Body(...)):

    # --------------------------------------------------------
    # 1. INVALID_SCHEMA
    # --------------------------------------------------------

    if not isinstance(payload, dict):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    if payload.get("channel") not in VALID_CHANNELS:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    if not isinstance(payload.get("output"), str):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    output = payload["output"]

    if len(output) > 20000:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA",
        }

    channel = payload["channel"]

    # --------------------------------------------------------
    # 2. ENCODED_PAYLOAD
    # --------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output and trips_channel_rule(channel, decoded):

        return {
            "safe": False,
            "reason": "ENCODED_PAYLOAD",
        }

    # --------------------------------------------------------
    # 3. CHANNEL RULES
    # --------------------------------------------------------

    if channel == "html":

        # SCRIPT_TAG
        if contains_script_tag(output):
            return {
                "safe": False,
                "reason": "SCRIPT_TAG",
            }

        # EVENT_HANDLER
        if contains_event_handler(output):
            return {
                "safe": False,
                "reason": "EVENT_HANDLER",
            }

        # DANGEROUS_SCHEME
        if dangerous_scheme(output):
            return {
                "safe": False,
                "reason": "DANGEROUS_SCHEME",
            }

        # EXTERNAL_EXFIL
        for url in extract_html_urls(output):

            if url_has_dangerous_scheme(url):
                return {
                    "safe": False,
                    "reason": "DANGEROUS_SCHEME",
                }

            if url_is_external_and_disallowed(url):
                return {
                    "safe": False,
                    "reason": "EXTERNAL_EXFIL",
                }

    elif channel == "markdown":

        # DANGEROUS_SCHEME
        if dangerous_scheme(output):
            return {
                "safe": False,
                "reason": "DANGEROUS_SCHEME",
            }

        # EXTERNAL_EXFIL
        for url in extract_markdown_urls(output):

            if url_has_dangerous_scheme(url):
                return {
                    "safe": False,
                    "reason": "DANGEROUS_SCHEME",
                }

            if url_is_external_and_disallowed(url):
                return {
                    "safe": False,
                    "reason": "EXTERNAL_EXFIL",
                }

    elif channel == "url":

        # DANGEROUS_SCHEME
        if dangerous_scheme(output):
            return {
                "safe": False,
                "reason": "DANGEROUS_SCHEME",
            }

        url = output.strip()

        if url_has_dangerous_scheme(url):
            return {
                "safe": False,
                "reason": "DANGEROUS_SCHEME",
            }

        # EXTERNAL_EXFIL
        if url_is_external_and_disallowed(url):
            return {
                "safe": False,
                "reason": "EXTERNAL_EXFIL",
            }

    elif channel == "sql":

        if contains_sql_metachar(output):
            return {
                "safe": False,
                "reason": "SQL_METACHAR",
            }

    elif channel == "shell":

        if contains_shell_metachar(output):
            return {
                "safe": False,
                "reason": "SHELL_METACHAR",
            }

    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    return {
        "safe": True,
        "reason": "SAFE",
    }