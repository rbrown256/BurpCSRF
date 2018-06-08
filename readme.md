Created by Rob Brown - https://twitter.com/RB256

# CSRF Extensions for Burp

- `csrf_oracle.py` - for when there's one endpoint on the site that gives you the CSRF token.
- `csrf_inline.py` - for when the token is provided in page responses.
- `csrf_inline_autorize.py` - for making other burp extensions compatible with inline CSRF tokens (e.g. the excellent autorize - https://github.com/Quitten/Autorize).
