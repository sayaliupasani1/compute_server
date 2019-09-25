import requests
import json
import urllib
from keycloak_params import *
import jwt

class Keycloak(object):

	"""
	Keycloak parameters/Variables

	------------

	base_uri: str
		Base URL for the keycloak server (For tests: http://localhost:8080)
	redirect_uri: str
		Redirection URL to provide after successful authentication
	realm: str
		Keycloak realm for this application
	client_id: str
		Keycloak client ID for this application
	client_secret: str
		Keycloak client secret when using confidential client

	"""

	def authenticate_user(self):
		"""
		The function creates a valid authorization endpoint URI.
		Users are redirected to this URI with required parameters, where Keycloak authenticates the user.
		In response, keycloak adds authorization code, which is used to fetch tokens

		"""
		params = {'client_id': client_id, 'redirect_uri': '{}/login'.format(redirect_uri), 'response_type':'code'}
		auth_url = '{0}/auth/realms/{1}/protocol/openid-connect/auth?'.format(base_uri, realm)
		# urllib to encode the parameters with URI
		auth_endpoint_url = auth_url + urllib.parse.urlencode(params)
		return auth_endpoint_url

	def get_access_token(self, auth_code):
		"""
		Takes the authorization code and exchanges it for access and refresh tokens.

		"""
		# Params required with token endpoint URI
		token_endpoint_params = {'grant_type':'authorization_code', 'code':auth_code, 'client_id': client_id, 'client_secret': client_secret, \
		'redirect_uri':'{}/login'.format(redirect_uri)}
		# Make request to Keycloak's token endpoint and pass authorization code in data
		tokens = requests.post('{0}/auth/realms/{1}/protocol/openid-connect/token'.format(base_uri, realm), data=token_endpoint_params)
		token_dict = json.loads(tokens.text)
		access_token = token_dict['access_token']
		refresh_token = token_dict['refresh_token']
		user_endpoint_params = {'access_token':access_token}
		# Make request to keycloak's user_info endpoint in order to fetch the username. We need to set this in cookie
		user_info = requests.post('{0}/auth/realms/{1}/protocol/openid-connect/userinfo'.format(base_uri, realm), data=user_endpoint_params)
		user_info_data = json.loads(user_info.text)
		username = user_info_data['preferred_username']
		return access_token, refresh_token, username

	def refresh_access_token(self, refresh_token):
		"""
		
		If the access token is expired and refresh token is valid, the token is validated and new access token is fetched.
		User's are not required to provide credentials for login.
		
		"""
		# parameters required along with token endpoint. The grant_type is refresh_token, which tells keycloak to validate the  \
		# refresh token and issue new access token
		refresh_token_endpoint_params = {'grant_type':'refresh_token', 'refresh_token':refresh_token, 'client_id': client_id, 'client_secret':client_secret}
		access_token_renewed = requests.post('{0}/auth/realms/{1}/protocol/openid-connect/token'.format(base_uri, realm),\
		data=refresh_token_endpoint_params)
		access_token_dict = json.loads(access_token_renewed.text)
		# If the refresh token is expired, Keycloak gives an error. Catch that error and re-authenticate user.
		if access_token_dict.get('error', False):
			print('Refresh token seems to be expired.. Authenticate again')
			return False
		else:
			access_token_new = access_token_dict['access_token']
			return access_token_new

	def verify_signature(self, access_token, refresh_token):

		"""

		If the user comes with access token, this verifies the signature. If verification results in error, refresh token is validated.
		Keycloak's introspect endpoint is used for validating the access token.

		"""
		# parameters required along with introspect endpoint URI
		introspect_data = {'token':access_token, 'client_id':client_id, 'client_secret': client_secret}
		user_info = requests.post('{0}/auth/realms/{1}/protocol/openid-connect/token/introspect'.format(base_uri, realm), data=introspect_data)
		user_info_data = json.loads(user_info.text)
		# If the access token is active, username is returned, which is cross verified with username cookie before serving the request.
		if user_info_data['active'] == True:
			verification_value = user_info_data['username']
			verification_code = 'username'
			return verification_code, verification_value
		# If access token is expired and refresh token exists, call the refresh_access_token function
		elif refresh_token != None:
			access_token_new = self.refresh_access_token(refresh_token)
			# The refresh_access_token function returns False if refresh token is expired and user needs to be re-authenticated
			if not access_token_new:
				verification_code = 'authenticate'
				verification_value = 'Null'
			else:
				verification_code = 'access_token_new'
				verification_value = access_token_new
			return verification_code, verification_value
		# If no refresh token exists, authenticate the user
		else:
			verification_code = 'authenticate'
			verification_value = 'Null'
			return verification_code, verification_value

	def verify_login(self, token):

		"""
		This function is called for each Flask route. This is to ensure that user's login is verified for each web page.
		To avoid multiple calls to Keycloak's introspect endpoint, this function performs manual token validation

		"""
		# Make request to keycloak's jwks endpoint, which returns the Json web key set
		jwk_uri = '{0}/auth/realms/{1}/protocol/openid-connect/certs'.format(base_uri, realm)
		jwks = requests.get(jwk_uri).json()
		public_keys = {}
		# Sort all the returned jwk into dictionary keyed with their KID. In this case, we are returned with a single key
		for jwk in jwks['keys']:
			kid = jwk['kid']
			public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
		# Get the Kid from access token - it tells which key was used to sign the token
		kid = jwt.get_unverified_header(token)['kid']
		# Use the same key to verify signature
		key = public_keys[kid]
		# The jwt decode throws an exception if it fails to verify signature. Catch the exception and authenticate user before serving the request.
		try:
			jwt_decode = jwt.decode(token, key=key, audience ='{}'.format(realm))
			print(jwt_decode)
			return True
		except:
			return False


	def logout_user(self):

		"""

		When user decides to logout, this function is called.
		It creates a redirection URI pointing towards keycloak's logout endpoint + required parameters.
		Users are redirected to this URI and keycloak handles logging out.

		"""
		logout_endpoint_params = {'redirect_uri': redirect_uri}
		logout_endpoint = '{0}/auth/realms/{1}/protocol/openid-connect/logout?'.format(base_uri, realm)
		logout_uri = logout_endpoint + urllib.parse.urlencode(logout_endpoint_params)
		return logout_uri