# a = ug.get_entity('users/{}'.format('2d6c6a3a-8bda-11e6-b1be-fb3622f06898'))
# print(a)

from usergrid import UserGrid
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import hashlib
import base64
import configparser
import flask
from flask import *
import requests
import re


app = Flask(__name__)

config = configparser.ConfigParser()
config.read('jsonapi-api.cfg')



@app.route('/auth/password/reset', methods=['GET'])
def reset_password_request():
    response = {}
    e = request.args.get('e')
    c = request.args.get('c')
    # email = base64.b64decode(bytes(e,'utf-8'))
    email = (base64.b64decode(bytes(e, 'utf-8'))).decode("utf-8")
    decryption = urldecryption(email)
    print(decryption, c, decryption==c)
    if decryption == c:
        response['status'] = True
    else:
        response['status'] = False
    response['e'] = e
    response['c'] = c
    response['email'] = email
    return render_template('index.html', data=response)
    # return render_template('index.html')

@app.route('/auth/newpassword/reset', methods=['POST'])
def request_password():
    e = request.form["e"]
    c = request.form["c"]
    password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]
    response = {}
    email = (base64.b64decode(bytes(e, 'utf-8'))).decode("utf-8")
    if password == confirm_password:
        decryption = urldecryption(email)
        if decryption == c:
            passwordvalidation = password_validation(password)
            if len(passwordvalidation) > 0:
                response['message'] = passwordvalidation[0]['detail']
                response['status'] = True
            elif update_password_to_usergrid(email, password) == 200:
                response['message'] = "Password is successfully set."
                response['status'] = True
            else:
                response['message'] = "Something went wrong, Please try again."
                response['status'] = True
        else:
            response['status'] = False
            response['message'] = "URL doesn't match."

    else:
        response['status'] = True
        response['e'] = e
        response['c'] = c
        response['email'] = email
        response['message'] = "Password and Confirm password doesn't match."
    return render_template('index.html', data=response)


def get_usergrid():
    ug_obj = UserGrid(host=config.get('usergrid', 'host'), port=config.get('usergrid', 'port'),
                      org=config.get('usergrid', 'org_name'), app=config.get('usergrid', 'app_name'),
                      autoreconnect=True)
    ug = ug_obj
    return ug

def update_password_to_usergrid(email, password):
    app_endpoint = "http://" + config.get('usergrid', 'host') + ":" + \
                    config.get('usergrid', 'port') + "/" + config.get('usergrid', 'org_name') + '/' + \
                   config.get('usergrid', 'app_name')

    ug = get_usergrid()
    ug.login(client_id=config.get('usergrid', 'client_id'), client_secret=config.get('usergrid', 'client_secret'))

    data = dict(newpassword=password)
    data = json.dumps(data)
    print(ug, dir(ug))
    url = app_endpoint + "/users/{}/password/".format(
        email) + "?client_id=" + config.get('usergrid', 'client_id') + "&client_secret=" + config.get('usergrid', 'client_secret')
    response = requests.put(url=url, data=data)
    print(response.status_code)
    return response.status_code


def urldecryption(email):
    salt = "thisisasecretphrase"
    mix = (salt + str(email)).encode('utf-8')
    hashvalue = hashlib.md5(mix).hexdigest()
    return hashvalue


def password_validation(p, errors=[]):
    if (len(p) < 8 or len(p) > 50):
        errors.append(dict(title="password length error",
                           detail="password strength should be minimum of 8 and maximum of 50 characters"))

    return errors


if __name__ == '__main__':
    app.run(debug=True, port=8001)
