import os
from google.auth.exceptions import GoogleAuthError

from urbangyan.core.views import fetch_current_affairs, post_to_blogspot


def test_fetch_and_post():
    # Test the fetch_current_affairs function
    print("Testing fetch_current_affairs...")
    news = fetch_current_affairs()
    if not news:
        print(
            "Failed to fetch current affairs. Check your API key or network connection."
        )
        return

    print(f"Fetched {len(news)} news articles:")
    for i, article in enumerate(news, start=1):
        print(f"{i}. {article['title']} - {article['url']}")

    # Test the post_to_blogspot function
    print("\nTesting post_to_blogspot...")
    try:
        post_url = post_to_blogspot(news)
        print(f"Blog post published successfully: {post_url}")
    except FileNotFoundError as e:
        print(
            f"File not found: {e}. Ensure the 'credentials' file is in the correct location."
        )
    except GoogleAuthError as e:
        print(
            f"Google authentication error: {e}. Check your credentials or token.json."
        )
    except Exception as e:
        print(f"An error occurred: {e}")


# Run the test
if __name__ == "__main__":
    test_fetch_and_post()
