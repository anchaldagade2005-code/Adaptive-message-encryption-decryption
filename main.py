import requests

# Make a request to a simple public API
response = requests.get('https://api.github.com/events')

# Print the status code to confirm it worked
print(f"Status Code: {response.status_code}")

# Print a portion of the response text
print("First 500 characters of response:")
print(response.text[:500])