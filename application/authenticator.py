import requests
import json
import urllib

class Keycloak(object):

	def authenticate_user(self):
		print('This is authenticate user function')
		params = {'client_id': 'compute_server', 'redirect_uri':'http://localhost:5000/login', 'response_type':'code'}
		auth_url = 'http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/auth?'
		auth_endpoint_url = auth_url + urllib.parse.urlencode(params)
		return auth_endpoint_url

	def get_access_token(self, auth_code):
		token_endpoint_params = {'grant_type':'authorization_code', 'code':auth_code, 'client_id':'compute_server', 'client_secret':'e853e2b4-004d-4a6a-bfce-dfd8bf0cbfc6', 'redirect_uri':'http://localhost:5000/login'}
		tokens = requests.post('http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/token', data=token_endpoint_params)
		token_dict = json.loads(tokens.text)
		#print('token dict:{}'.format(token_dict))
		access_token = token_dict['access_token']
		refresh_token = token_dict['refresh_token']
		user_endpoint_params = {'access_token':access_token}
		user_info = requests.post('http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/userinfo', data=user_endpoint_params)
		#print('User info: {}'.format(user_info.text))
		user_info_data = json.loads(user_info.text)
		username = user_info_data['preferred_username']
		return access_token, refresh_token, username

	def refresh_access_token(self, refresh_token):
		refresh_token_endpoint_params = {'grant_type':'refresh_token', 'refresh_token':refresh_token, 'client_id':'compute_server', 'client_secret':'e853e2b4-004d-4a6a-bfce-dfd8bf0cbfc6'}
		access_token_renewed = requests.post('http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/token', data=refresh_token_endpoint_params)
		access_token_dict = json.loads(access_token_renewed.text)
		#print('access_token_dict:{}'.format(access_token_dict))
		if access_token_dict.get('error', False):
			print('Refresh token seems to be expired.. Authenticate again')
			return False
		else:
			access_token_new = access_token_dict['access_token']
			return access_token_new

	def verify_signature(self, access_token, refresh_token):
		#print('this is in verify_signature')
		#print(access_token)
		introspect_data = {'token':access_token, 'client_id':'compute_server', 'client_secret':'e853e2b4-004d-4a6a-bfce-dfd8bf0cbfc6'}
		user_info = requests.post('http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/token/introspect', data=introspect_data)
		user_info_data = json.loads(user_info.text)
		#print('user info in verify signature:{}'.format(user_info_data))
		#print(user_info_data['active'])
		if user_info_data['active'] == True:
			verification_value = user_info_data['username']
			print('verified_username:{}'.format(verification_value))
			verification_code = 'username'
			return verification_code, verification_value
		elif refresh_token != None:
			access_token_new = self.refresh_access_token(refresh_token)
			#print('New access token:{}'.format(access_token_new))
			if not access_token_new:
				verification_code = 'authenticate'
				verification_value = 'Null'
			else:
				verification_code = 'access_token_new'
				verification_value = access_token_new
			return verification_code, verification_value
		else:
			verification_code = 'authenticate'
			verification_value = 'Null'
			return verification_code, verification_value

	def logout_user(self):
		print('You hit kc logout user func')
		logout_endpoint_params = {'redirect_uri':'http://localhost:5000'}
		logout_endpoint = 'http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/logout?'
		logout_uri = logout_endpoint + urllib.parse.urlencode(logout_endpoint_params)
		return logout_uri