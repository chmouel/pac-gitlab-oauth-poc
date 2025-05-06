import os

import requests

# --- GitLab OAuth Configuration ---
# Replace with your actual GitLab OAuth app details
GITLAB_CLIENT_ID = os.environ.get("GITLAB_CLIENT_ID", "YOUR_GITLAB_CLIENT_ID")
GITLAB_CLIENT_SECRET = os.environ.get(
    "GITLAB_CLIENT_SECRET", "YOUR_GITLAB_CLIENT_SECRET"
)
GITLAB_URL = os.environ.get(
    "GITLAB_URL", "https://gitlab.com"
)  # Your GitLab instance URL

# OAuth Endpoints
GITLAB_TOKEN_URL = f"{GITLAB_URL}/oauth/token"


def refresh_gitlab_access_token(refresh_token: str) -> dict:
    """
    Exchanges a GitLab refresh token for a new access token.

    Args:
        refresh_token: The refresh token obtained during the OAuth flow.

    Returns:
        A dictionary containing the new token information (access_token,
        refresh_token, expires_in, etc.) or raises an HTTPError.
    """
    token_data = {
        "client_id": GITLAB_CLIENT_ID,
        "client_secret": GITLAB_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    response = requests.post(GITLAB_TOKEN_URL, data=token_data)
    response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

    return response.json()


# --- Example Usage ---
def main():
    refresh_token = os.environ.get("GITLAB_REFRESH_TOKEN")
    if not refresh_token:
        print("Please set GITLAB_REFRESH_TOKEN environment variable.")
        exit(1)

    if (
        "YOUR_GITLAB_CLIENT_ID" in GITLAB_CLIENT_ID
        or "YOUR_GITLAB_CLIENT_SECRET" in GITLAB_CLIENT_SECRET
    ):
        print(
            "Please set GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET environment variables or replace placeholders."
        )
        exit(1)

    try:
        print(
            f"Attempting to refresh token using: {refresh_token[:5]}..."
        )  # Print truncated token
        new_token_info = refresh_gitlab_access_token(refresh_token)

        print("\nSuccessfully refreshed token!")
        print(new_token_info)

        # The new_token_info dictionary will contain the new 'access_token',
        # and potentially a new 'refresh_token' depending on GitLab's policy.

    except requests.exceptions.RequestException as e:
        print(f"\nError refreshing token: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
