import docker
from flask import Flask
from flask import request
from flask import render_template
import json
import pandas as pd
import random


docker_client = docker.from_env()

#Creating an object for low-level docker-py API
docker_api = docker.APIClient(base_url=None) 

app = Flask(__name__)
assigned_ports = []

@app.route('/')
def landing_page():
	return render_template('landing.html')

@app.route('/listOfContainers.html')
def listcon():
	container_dict = {}
	df_html = "You have no running containers currently."
	container_list = docker_api.containers(trunc=True)
	for x in container_list:
		container_dict[x['Id']] = {"Container_Id":x['Id'], "Image":x['Image'], "Container_Name":x['Names'], "Port":x['Ports'][0]['PublicPort']}
		df = pd.DataFrame(container_dict)
		df_html = df.to_html()
	return render_template('listOfContainers.html', table_html=df_html)

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
	print(container_name)
	print(container_port)
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


if __name__=='__main__':
	app.run(debug=True)