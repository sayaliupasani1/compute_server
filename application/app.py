import docker
from flask import Flask
from flask import request
from flask import render_template
import json


docker_client = docker.from_env()

#Creating an object for low-level docker-py API
docker_api = docker.APIClient(base_url=None) 

app = Flask(__name__)

@app.route('/')
def landing_page():
	return render_template('landing.html')

@app.route('/listcontainers')
def listcon():
		render_template('listOfContainers.html')

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
			create_container(image)
			return render_template('created_container.html', image=image, container_name=container_data[0], container_port=container_data[1])

def create_container(image):
	container = docker_client.containers.run(image, ports = {22:2222}, detach=True, remove=True)
	container_name = container.name
	container_port = docker_api.inspect_container(container.id)['NetworkSettings']['Ports']['22/tcp']
	print(container_name)
	print(container_port)
	return container_name, container_port


if __name__=='__main__':
	app.run(debug=True)