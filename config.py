import os

import secret

# Layout Directory Structure
BASE_DIR = os.path.dirname(os.path.realpath(__file__)) + '/app'
HOOK_DIR = '{}/hooks'.format(BASE_DIR)

# I dont want to have to keep making git changes to switch debug mode
DEBUG = secret.DEBUG

# GitHub API for IP Whitelist
WHITELIST_IP_URL = 'https://api.github.com/meta'
GITHUB_WEBHOOK_SECRET_KEY = secret.GITHUB_WEBHOOK_SECRET_KEY
VERIFY_GITHUB = True
