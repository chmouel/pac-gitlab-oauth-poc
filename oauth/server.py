#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "flask",
#     "requests", # Added requests for making HTTP calls
# ]
# ///
import base64  # To safely encode/decode state data
import os
import uuid  # To generate a state parameter for security

import requests
from flask import Flask, jsonify, redirect, request, session

app = Flask(__name__)
# In a real application, use a strong, randomly generated secret key
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "never-gonna-give-xxaaa22")

# --- GitLab OAuth Configuration ---
# Replace with your actual GitLab OAuth app details
GITLAB_CLIENT_ID = os.environ.get("GITLAB_CLIENT_ID", "YOUR_GITLAB_CLIENT_ID")
GITLAB_CLIENT_SECRET = os.environ.get(
    "GITLAB_CLIENT_SECRET", "YOUR_GITLAB_CLIENT_SECRET"
)
# This MUST be a single, fixed Redirect URI registered in your GitLab app settings
GITLAB_REDIRECT_URI = os.environ.get(
    "GITLAB_REDIRECT_URI", "http://localhost:8080/callback/gitlab"
)
GITLAB_URL = os.environ.get(
    "GITLAB_URL", "https://gitlab.com"
)  # Your GitLab instance URL

# OAuth Endpoints
GITLAB_AUTHORIZE_URL = f"{GITLAB_URL}/oauth/authorize"
GITLAB_TOKEN_URL = f"{GITLAB_URL}/oauth/token"


@app.route("/")
def index():
    """Basic index page with example link to initiate GitLab login for a repo."""
    # Example link to initiate OAuth for a specific namespace and repo
    example_ns = "my-project-namespace"
    example_repo = "my-gitlab-repository"
    return f'Click here to login for {example_ns}/{example_repo}: <p><a href="/oauth/{example_ns}/{example_repo}">Login with GitLab for {example_ns}/{example_repo}</a></p>'


# Modified route to accept namespace and repository name
@app.route("/oauth/<string:namespace>/<string:repository>", methods=["GET"])
def initiate_oauth(namespace, repository):
    """Initiates the GitLab OAuth flow, including namespace and repository in state."""
    # Generate a unique identifier for this request
    session_uuid = str(uuid.uuid4())

    # Create a state parameter that includes context and the unique identifier
    # We'll use a simple structure like "uuid|namespace|repository"
    # Encode the state to be URL-safe
    contextual_state = f"{session_uuid}|{namespace}|{repository}"
    encoded_state = base64.urlsafe_b64encode(contextual_state.encode()).decode()

    # Store the UUID part of the state in the session for validation later
    session["oauth_state_uuid"] = session_uuid
    # Also store the intended context to double-check in the callback
    session["oauth_context"] = {"namespace": namespace, "repository": repository}

    auth_url = (
        f"{GITLAB_AUTHORIZE_URL}?"
        f"client_id={GITLAB_CLIENT_ID}&"
        f"redirect_uri={GITLAB_REDIRECT_URI}&"
        f"response_type=code&"
        f"state={encoded_state}&"  # Use the encoded state
        "scope=api"  # Define the required scopes
    )
    print(f"Redirecting to: {auth_url}")
    return redirect(auth_url)


@app.route("/callback/gitlab", methods=["GET"])
def callback_gitlab():
    """Handles the redirect from GitLab after authorization and processes state."""
    received_encoded_state = request.args.get("state")
    code = request.args.get("code")
    error = request.args.get("error")

    # Retrieve expected UUID and context from session
    expected_uuid = session.pop("oauth_state_uuid", None)
    expected_context = session.pop("oauth_context", None)

    if error:
        error_description = request.args.get("error_description", "")
        print(f"OAuth Error: {error} - {error_description}")
        # Clear any remaining session state
        session.pop("oauth_state_uuid", None)
        session.pop("oauth_context", None)
        return jsonify({"error": error, "error_description": error_description}), 400

    if not received_encoded_state or not code:
        print("Missing state or code in callback")
        return jsonify({"error": "Missing state or code"}), 400

    # Decode and validate the state parameter
    try:
        decoded_state_bytes = base64.urlsafe_b64decode(received_encoded_state)
        decoded_state = decoded_state_bytes.decode()
        # Split the state back into its components
        state_parts = decoded_state.split("|")
        if len(state_parts) != 3:
            raise ValueError("Invalid state format")
        received_uuid, namespace, repository = state_parts

        # Validate the UUID against the one stored in the session
        if received_uuid != expected_uuid:
            print(
                f"State mismatch: Received UUID {received_uuid}, Expected UUID {expected_uuid}"
            )
            return jsonify({"error": "Invalid state parameter (UUID mismatch)"}), 400

        # Optionally validate the context against the one stored in the session
        if expected_context and (
            namespace != expected_context.get("namespace")
            or repository != expected_context.get("repository")
        ):
            print(
                f"Context mismatch: Received {namespace}/{repository}, Expected {expected_context.get('namespace')}/{expected_context.get('repository')}"
            )
            # This might indicate a subtle issue or just a user navigating away
            # Decide if this should be a hard error based on your security requirements
            pass  # Allow to proceed but log the discrepancy

    except Exception as e:
        print(f"Error decoding or validating state: {e}")
        # Clear any remaining session state
        session.pop("oauth_state_uuid", None)
        session.pop("oauth_context", None)
        return jsonify({"error": "Invalid state parameter"}), 400

    # Exchange the authorization code for an access token
    token_data = {
        "client_id": GITLAB_CLIENT_ID,
        "client_secret": GITLAB_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": GITLAB_REDIRECT_URI,
    }

    try:
        response = requests.post(GITLAB_TOKEN_URL, data=token_data)
        response.raise_for_status()  # Raise an exception for bad status codes
        token_info = response.json()

        # --- Here you have the tokens and the context! ---
        # You now have the namespace and repository from the state:
        # print(f"Authorized for Namespace: {namespace}, Repository: {repository}")
        # print(f"Received Token Info: {token_info}")

        # In a real PAC application, you would:
        # 1. Securely store token_info (access_token, refresh_token)
        # 2. Associate these tokens with the {namespace}/{repository} context.
        # 3. Update or create the Repository CR in the cluster.

        return jsonify(
            {
                "message": "Successfully obtained access token",
                "authorized_for": {"namespace": namespace, "repository": repository},
                "token_info": token_info,
            }
        )

    except requests.exceptions.RequestException as e:
        print(f"Error exchanging code for token: {e}")
        return jsonify(
            {"error": "Failed to obtain access token", "details": str(e)}
        ), 500


# The original catch_all route can remain for debugging other requests if needed
@app.route(
    "/<path:path>",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
def catch_all(path):
    # ... (original print and jsonify logic) ...
    print("\n=== Request Details ===")
    print(f"Method: {request.method}")
    print(f"Path: /{path}")
    print("Headers:")
    for key, value in request.headers.items():
        print(f"  {key}: {value}")

    if request.is_json:
        print("JSON Body:")
        print(request.json)
    else:
        print("Body (Raw):")
        print(request.data.decode("utf-8"))

    return jsonify(
        {
            "message": "Request received by catch-all",
            "method": request.method,
            "path": f"/{path}",
            "headers": dict(request.headers),
            "json_body": request.json if request.is_json else None,
        }
    ), 200


def main():
    # Remember to set FLASK_SECRET_KEY, GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET, and GITLAB_REDIRECT_URI
    # in your environment variables before running in production.
    # For local testing, you can uncomment and set them directly here, but this is not recommended for production.
    # os.environ["FLASK_SECRET_KEY"] = "replace-with-a-proper-secret"
    # os.environ["GITLAB_CLIENT_ID"] = "..."
    # os.environ["GITLAB_CLIENT_SECRET"] = "..."
    # os.environ["GITLAB_REDIRECT_URI"] = "http://localhost:8080/callback/gitlab" # Must match GitLab app setting
    # os.environ["GITLAB_URL"] = "https://gitlab.com"

    # In a real PAC controller, you would run this indefinitely as a service
    app.run(host="0.0.0.0", port=8080, debug=True)


if __name__ == "__main__":
    main()
