#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "flask",
#     "requests", # Added requests for making HTTP calls
# ]
# ///
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
GITLAB_REDIRECT_URI = os.environ.get(
    "GITLAB_REDIRECT_URI", "http://localhost:8080/callback/gitlab"
)  # This MUST match the Redirect URI in your GitLab app settings
GITLAB_URL = os.environ.get(
    "GITLAB_URL", "https://gitlab.com"
)  # Your GitLab instance URL

# OAuth Endpoints
GITLAB_AUTHORIZE_URL = f"{GITLAB_URL}/oauth/authorize"
GITLAB_TOKEN_URL = f"{GITLAB_URL}/oauth/token"


@app.route("/")
def index():
    """Basic index page with a link to initiate GitLab login."""
    return '<a href="/login/gitlab">Login with GitLab</a>'


@app.route("/login/gitlab")
def login_gitlab():
    """Initiates the GitLab OAuth flow."""
    # Generate a unique state parameter to prevent CSRF attacks
    state = str(uuid.uuid4())
    session["oauth_state"] = state  # Store state in session

    auth_url = (
        f"{GITLAB_AUTHORIZE_URL}?"
        f"client_id={GITLAB_CLIENT_ID}&"
        f"redirect_uri={GITLAB_REDIRECT_URI}&"
        f"response_type=code&"
        f"state={state}&"
        "scope=api"  # Define the required scopes (e.g., api, read_user, read_repository)
    )
    return redirect(auth_url)


@app.route("/callback/gitlab")
def callback_gitlab():
    """Handles the redirect from GitLab after authorization."""
    # Validate the state parameter
    received_state = request.args.get("state")
    expected_state = session.pop(
        "oauth_state", None
    )  # Remove state from session after checking

    if received_state != expected_state:
        return jsonify(
            {"error": "Invalid state parameter"}
        ), 400  # CSRF attack possibility

    code = request.args.get("code")
    if not code:
        error = request.args.get("error", "Unknown error")
        error_description = request.args.get("error_description", "")
        return jsonify({"error": error, "error_description": error_description}), 400

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

        # --- Here you have the tokens! ---
        # token_info will typically contain:
        # "access_token": "...",
        # "token_type": "bearer",
        # "expires_in": 7200, # Token lifetime in seconds
        # "refresh_token": "...", # If the 'offline_access' scope was requested
        # "scope": "api"

        access_token = token_info.get("access_token")
        # Store this access_token securely and associate it with the user
        # Use this token to make API calls to GitLab on behalf of the user

        return jsonify(
            {"message": "Successfully obtained access token", "token_info": token_info}
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
    # os.environ["GITLAB_REDIRECT_URI"] = "http://localhost:8080/callback/gitlab"
    # os.environ["GITLAB_URL"] = "https://gitlab.com"
    app.run(host="0.0.0.0", port=8080, debug=True)


if __name__ == "__main__":
    main()
