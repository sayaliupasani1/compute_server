import requests
import json
import urllib
from keycloak_params import *
import jwt

class Keycloak(object):

	def authenticate_user(self):
		print('This is authenticate user function')
		params = {'client_id': client_id, 'redirect_uri': auth_redirect_uri, 'response_type':'code'}
		auth_url = 'http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/auth?'
		auth_endpoint_url = auth_url + urllib.parse.urlencode(params)
		return auth_endpoint_url

	def get_access_token(self, auth_code):
		token_endpoint_params = {'grant_type':'authorization_code', 'code':auth_code, 'client_id': client_id, 'client_secret': client_secret, 'redirect_uri':auth_redirect_uri}
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
		refresh_token_endpoint_params = {'grant_type':'refresh_token', 'refresh_token':refresh_token, 'client_id': client_id, 'client_secret':client_secret}
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
		introspect_data = {'token':access_token, 'client_id':client_id, 'client_secret': client_secret}
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

	def verify_login(self, token):
		jwk_uri = 'http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/certs'
		jwks = requests.get(jwk_uri).json()
		#print('This is jwks:{}'.format(jwks))
		public_keys = {}
		for jwk in jwks['keys']:
			kid = jwk['kid']
			public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
		#print('This is public key dict:{}'.format(public_keys))
		kid = jwt.get_unverified_header(token)['kid']
		key = public_keys[kid]
		#print('This is key:{}'.format(key))
		try:
			jwt_decode = jwt.decode(token, key=key, audience ='compute_server')
			print(jwt_decode)
			return True
		except:
			return False


	def logout_user(self):
		print('You hit kc logout user func')
		logout_endpoint_params = {'redirect_uri': logout_redirect_uri}
		logout_endpoint = 'http://localhost:8080/auth/realms/compute_server/protocol/openid-connect/logout?'
		logout_uri = logout_endpoint + urllib.parse.urlencode(logout_endpoint_params)
		return logout_uri