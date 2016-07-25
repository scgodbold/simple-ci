import glob
import hmac
import requests
import subprocess

from flask import Flask, request, jsonify, abort
from hashlib import sha1
from IPy import IP

app = Flask(__name__)
app.config.from_object('config')


class DeployError(Exception):
    '''Contains data about deployment failures'''


def verify_ip(remote_addr):
    remote = IP(remote_addr)
    whitelist = [IP(x) for x in requests.get(app.config['WHITELIST_IP_URL']).json()['hooks']]
    for ip in whitelist:
        if remote in ip:
            break
    else:
        abort(403)
    return True


def verify_payload(data, header_sig):
    sha_type, signature = header_sig.split('=')
    if signature is None or sha_type != 'sha1':
        abort(403)

    # create our mac
    mac = hmac.new(str(app.config['GITHUB_WEBHOOK_SECRET_KEY']), msg=data, digestmod=sha1)

    # Test the mac
    try:
        if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
            abort(403)
    except:
        # no compare_digest do bad compare instead (I am lazy)
        if str(mac.hexdigest()) != str(signature):
            abort(403)
    return True


def determine_action(repo, branch):
    # Possible names, can add more later
    file_names = [
        '{}_{}'.format(repo, branch),
        repo,
    ]

    matches = glob.glob('{}/{}*'.format(app.config['HOOK_DIR'], repo))
    for opt in file_names:
        found = [x for x in matches if opt.lower() in x.lower()]
        if len(found) > 1:
            abort(500)
        elif len(found) == 1:
            return found[0]
    return None


def take_action(action):
    proc = subprocess.Popen(action, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return_code = proc.returncode
    if return_code != 0:
        # Script did not exit cleanly, sound the alarms
        raise DeployError('Script returned with exit code {}:\n\n{}'.format(return_code, stderr))


def notify(message):
    print message


@app.route('/', methods=['POST'])
def simple_ci():
    try:
        payload = {
            'message': 'Push notification proccessed!',
        }
        if app.config['VERIFY_GITHUB']:
            verify_ip(request.remote_addr)
            verify_payload(request.data, request.headers.get('X-Hub-Signature'))

        # Determine what action to take
        json = request.get_json()
        branch = json['refs'].split('/')[-1]  # Last element is the branch
        repo = json['repository']['name']
        action = determine_action(repo, branch)
        if action is not None:
            take_action(action)
    except DeployError as e:
        # If an exception happens, this means that deploy has failed
        # We must notify that this has happened
        message = 'Deploy failed for: {}/{}\n'
        message += '===============================================================\n\n{}'
        message = message.format(repo, branch, e.message)
        notify(message)
    except TypeError:
        # Request wasn't formatted properly abort
        abort(403)
    return jsonify(payload)
