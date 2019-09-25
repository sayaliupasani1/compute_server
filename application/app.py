import docker
from flask import *
from flask import Flask
from flask import request, redirect, make_response
from flask import render_template
import urllib
import json
import pandas as pd
import random
import requests
from authenticator import Keycloak as kc

####

"""Main packages:
 - Creating and managing docker containers - docker-py
 - Serving web pages - Flask
- Authenticating users - Keycloak. This is implemented using requests library to make calls to the keycloak endpoint.

"""

####

docker_client = docker.from_env()

#Creating an object for low-level docker-py API
docker_api = docker.APIClient(base_url=None) 

app = Flask(__name__)
assigned_ports = []

@app.route('/')
def landing():
	"""
	On base path, the first step will include checking for access token and validating it.
	If the token is valid, landing page is rendered without credential authentication.
	If token is not valid and/or expired, the users are redirected to /login.
	"""
	if request.cookies.get('access_token') and request.cookies.get('username'):
		access_token = request.cookies.get('access_token')
		refresh_token = request.cookies.get('refresh_token')
		username = request.cookies.get('username')
		# The verification can result in one of the following: access token valid, refresh token valid, need to re-authenticate user
		verification_code, verification_value = kc().verify_signature(access_token, refresh_token)
		if verification_code == 'username' and verification_value == username:
			return render_template('landing.html')
		# If refresh token is valid, users are served with the requested page along with setting a new access token
		elif verification_code == 'access_token_new':
			access_token_new = verification_value
			response = make_response(redirect(url_for('landing')))
			response.set_cookie('access_token', access_token_new)
			return response
		# If access token and refresh token are expired, user is redirected to /login where they pass through complete authentication
		elif verification_code == 'authenticate':
			return redirect(url_for('login'))
	else:
		auth_url = kc().authenticate_user()
		return redirect(auth_url)

@app.route('/login')
def login():
	"""
	If users come with authorization code (after keycloak redirection), the landing page is served along \
	with setting access token. refresh token and username in cookie.

	This function calls get_access_token function to fetch the tokens from Keycloak.

	"""
	if request.args.get('code'):
		session_state = request.args.get('session_state')
		auth_code = request.args.get('code')
		# call the get_access_token for exchanging authorization code for access and refresh tokens
		access_token, refresh_token, username = kc().get_access_token(auth_code)
		response = make_response(render_template('landing.html'))
		# Set the tokens as cookies in the response
		response.set_cookie('access_token', access_token)
		response.set_cookie('refresh_token', refresh_token)
		response.set_cookie('username', username)
		return response
	else:
		# If user request does not have authorization code, they are authenticated - send to keycloak who sets the auth code
		auth_url = kc().authenticate_user()
		return redirect(auth_url)

@app.route('/listOfContainers.html')
def listcon(): 
	"""
	This function serves the page for listing currently running user's containers.
	If users come with access token, the token is manually validated using pyJWT before rendering the page.
	If the signature is expired, users are redirected to /login where pass through complete authentication process.

	"""
	if request.cookies.get('access_token'):
		token = request.cookies.get('access_token')
		verify_token = kc().verify_login(token)
		# If access token is valid, verify_login function returns True, and the container list is calculated and served
		if verify_token:
			container_dict = {}
			df_html = "You have no running containers currently."
			container_list = docker_api.containers(trunc=True)
			for x in container_list:
				public_port_list = [d['PublicPort'] for d in x['Ports'] if 'PublicPort' in d]
				public_port = public_port_list[0]
				container_dict[x['Id']] = {"Container_Id":x['Id'], "Image":x['Image'], "Container_Name":x['Names'], "Port":public_port}
			df = pd.DataFrame(container_dict)
			df_html = df.to_html()
			return render_template('listOfContainers.html', table_html=df_html)
		if not verify_token:
			return redirect(url_for('login'))
	else:
		return redirect(url_for('login'))

@app.route('/containerdetails.html', methods=['GET', 'POST'])
def get_containerdetails():
	"""
	This function takes container details as user input based on which, the container is created.
	"""
	if request.method == 'GET':
		return render_template('containerDetails.html')
	if request.method == 'POST':
		#con_details = {}
		image_name = request.form['image_name']
		if image_name == 'ubuntu': # Currently, users are being provided with only two image options
			image = 'rastasheep/ubuntu-sshd:16.04'
			# Call create_container function to create a container using specified image/requirements
			container_data = create_container(image)
			return render_template('created_container.html', image=image, container_name=container_data[0], container_port=container_data[1])
		elif image_name == 'apache':
			image = 'httpd:latest'
			container_data = create_container(image)
			return render_template('created_container.html', image=image, container_name=container_data[0], container_port=container_data[1])

def create_container(image):
	"""
	This function is to create a container with specified image.
	The container is create with port forwarding on host so that user's can use relevant port to drop into SSH shell of their container.
	It returns the container details that are being displayed to the user.

	"""
	# The for loop is to decide the host port. The already assigned ports are tracked in the list.
	for i in range(1025, 49152):
		port = random.randint(1025, 49152)
		if port not in assigned_ports:
			assigned_ports.append(port)
			break
	""" Using docker-py for creating and managing docker containers - Below call creates a container with specified image and port forwarding
	The remove flag ensures to remove the container after it has been stopped """
	container = docker_client.containers.run(image, ports = {22:port}, detach=True, remove=True)
	container_name = container.name
	# Inspect the created container for specific details to be provided to the user
	container_port = docker_api.inspect_container(container.id)['NetworkSettings']['Ports']['22/tcp']
	return container_name, container_port

@app.route('/deletecontainer.html', methods=['GET', 'POST'])
def deletecontainer():
	"""
	This function is to delete specified container. User is asked to input the container ID to be deleted
	"""
	if request.method == 'GET':
		return render_template('containertodelete.html')
	if request.method == 'POST':
		container_id = request.form['container_id']
		# Create a container object for specified container ID
		cont_obj = docker_client.containers.get(container_id)
		# Stop the container using object
		cont_obj.stop()
		return render_template('deletecontainer.html')

@app.route('/logout')
def logout():
	"""
	This function is to logout the users. Called when user's click on the 'logout' button.
	It makes a call to keycloak authenticator's logout_user function, which ensures that keycloak is aware of user logout.
	In response, the username, access_token and refresh_token cookies are removed.

	"""
	logout_uri = kc().logout_user()
	logout_response = redirect(logout_uri)
	logout_response.set_cookie('username', expires=0)
	logout_response.set_cookie('access_token', expires=0)
	logout_response.set_cookie('refresh_token', expires=0)
	return logout_response

# Runs flask
if __name__=='__main__':
	app.run(debug=True)