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

docker_client = docker.from_env()

#Creating an object for low-level docker-py API
docker_api = docker.APIClient(base_url=None) 

app = Flask(__name__)
assigned_ports = []

@app.route('/')
def landing():
	if request.cookies.get('access_token') and request.cookies.get('username'):
		#print('access_token present')
		access_token = request.cookies.get('access_token')
		refresh_token = request.cookies.get('refresh_token')
		username = request.cookies.get('username')
		#print('Refresh token in login func: {}'.format(refresh_token))
		verification_code, verification_value = kc().verify_signature(access_token, refresh_token)
		#print('verification_value:{}'.format(verification_value))
		if verification_code == 'username' and verification_value == username:
			return render_template('landing.html')
		elif verification_code == 'access_token_new':
			#print('This is new access token')
			access_token_new = verification_value
			response = make_response(redirect(url_for('landing')))
			response.set_cookie('access_token', access_token_new)
			return response
		elif verification_code == 'authenticate':
			return redirect(url_for('login'))
	else:
		auth_url = kc().authenticate_user()
		return redirect(auth_url)

@app.route('/login')
def login():
	print('This is login func')
	if request.args.get('code'):
		session_state = request.args.get('session_state')
		auth_code = request.args.get('code')
		#print('Authorization code:{}'.format(auth_code))
		access_token, refresh_token, username = kc().get_access_token(auth_code)
		response = make_response(render_template('landing.html'))
		response.set_cookie('access_token', access_token)
		response.set_cookie('refresh_token', refresh_token)
		response.set_cookie('username', username)
		#print('Access token in landing page func:{}'.format(access_token))
		#print('Refresh token in landing page func:{}'.format(refresh_token))
		return response
	else:
		auth_url = kc().authenticate_user()
		return redirect(auth_url)

@app.route('/listOfContainers.html')
def listcon(): 
	if request.cookies.get('access_token'):
		token = request.cookies.get('access_token')
		verify_token = kc().verify_login(token)
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
	if request.method == 'GET':
		return render_template('containerDetails.html')
	if request.method == 'POST':
		#con_details = {}
		image_name = request.form['image_name']
		if image_name == 'ubuntu':
			image = 'rastasheep/ubuntu-sshd:16.04'
			container_data = create_container(image)
			return render_template('created_container.html', image=image, container_name=container_data[0], container_port=container_data[1])
		elif image_name == 'apache':
			image = 'httpd:latest'
			container_data = create_container(image)
			return render_template('created_container.html', image=image, container_name=container_data[0], container_port=container_data[1])

def create_container(image):
	for i in range(1025, 49152):
		port = random.randint(1025, 49152)
		if port not in assigned_ports:
			assigned_ports.append(port)
			break
	container = docker_client.containers.run(image, ports = {22:port}, detach=True, remove=True)
	container_name = container.name
	container_port = docker_api.inspect_container(container.id)['NetworkSettings']['Ports']['22/tcp']
	return container_name, container_port

@app.route('/deletecontainer.html', methods=['GET', 'POST'])
def deletecontainer():
	if request.method == 'GET':
		return render_template('containertodelete.html')
	if request.method == 'POST':
		container_id = request.form['container_id']
		cont_obj = docker_client.containers.get(container_id)
		cont_obj.stop()
		return render_template('deletecontainer.html')

@app.route('/logout')
def logout():
	print('you hit flask logout func')
	logout_uri = kc().logout_user()
	logout_response = redirect(logout_uri)
	logout_response.set_cookie('username', expires=0)
	logout_response.set_cookie('access_token', expires=0)
	logout_response.set_cookie('refresh_token', expires=0)
	return logout_response


if __name__=='__main__':
	app.run(debug=True)