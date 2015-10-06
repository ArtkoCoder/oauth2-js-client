/**
 * OAuth 2.0 Client v0.2.4
 *
 * Copyright (c) 2015 Artkosoft - Artur Kozubski
 *
 * Released under the terms of MIT License:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * OAuth 2.0 simple client with Bearer token support, based on the jQuery AJAX client.
 *
 * @author Artur Kozubski (a.kozubski@artkosoft.pl) [Dec 14, 2014 1:33:38 PM]
 * @copyright Copyright (c) 2015 Artkosoft - Artur Kozubski (http://artkosoft.pl)
 * @license MIT License - Artur Kozubski (http://artur-kozubski.net)
 */

// Artkosoft namespace
var Artkosoft = Artkosoft || {};

!function(factory) {
	if (typeof define === 'function' && define.amd) {
		// Expose as an AMD module with jQuery dependency.
		define(['jquery'], factory);
	} else {
		// No AMD-compliant loader.
		factory(jQuery);
	}
}(function($) {
	'use strict';

	Artkosoft.OAuth2Client = function(options) {
		/* Private properties */

		var that = this;
		var lastRequest = null;
		var clientOptions = $.extend({
			protocol: 'http',
			host: 'localhost',
			tokenEndpoint: '/oauth2/token',
			authorizeEndpoint: '/oauth2/authorize',
			revokeEndpoint: '/oauth2/revoke',
			clientId: null,
			clientSecret: null,
			localStoragePrefix: 'artkosoft.oauth2.',
			authorizeCallback: function() { console.warn('API access denied! Action requires authorization. Override this callback with custom function by authorizeCallback option.'); },
			rememberUser: false
		}, options);

		if (clientOptions.host.slice(-1) == '/') {
			clientOptions.host = clientOptions.host.substr(0, clientOptions.host.length - 1);
		}
		if (localStorage.getItem(clientOptions.localStoragePrefix + 'remember_user') !== null) {
			clientOptions.rememberUser = localStorage.getItem(clientOptions.localStoragePrefix + 'remember_user');
		}

		/* Private methods */

		/**
		 * Parses authenticate HTTP header returned by OAuth 2.0 server.
		 *
		 * @param {String} value
		 * @param {String} scheme
		 */
		function parseAuthenticateHeader(value, scheme)
		{
			if (!value) return null;

			var regExp = /([a-z_\d]+)(=("([^\\"]*(\\.)?)*")|[a-z_\d]*)?(,)?(\s+|$)/i;
			var methods = [], method = null;

			while (value.length) {
				var term = regExp.exec(value);
				value = value.substr(term[0].length);
				if (!term[6] && term[7]) {
					method = { scheme: term[1], params: {} };
					methods.push(method);
				} else {
					if (term[3].match(/^"/)) term[3] = term[3].substr(1, term[3].length - 2);
					method.params[term[1]] = term[3].replace(/\\"/, '"');
				}
			}

			if (scheme) {
				for (var i = 0; i < methods.length; i++) {
					if (methods[i].scheme == scheme) return methods[i].params;
				}

				return null;
			}

			return methods;
		}

		/**
		 * Returns access token stored in the local storage.
		 *
		 * @returns {String}
		 */
		function getAccessToken()
		{
			return clientOptions.rememberUser ? localStorage.getItem(clientOptions.localStoragePrefix + 'access_token') : sessionStorage.getItem(clientOptions.localStoragePrefix + 'access_token');
		}

		/**
		 * Returns refresh token stored in the local storage.
		 *
		 * @returns {String}
		 */
		function getRefreshToken()
		{
			return clientOptions.rememberUser ? localStorage.getItem(clientOptions.localStoragePrefix + 'refresh_token') : sessionStorage.getItem(clientOptions.localStoragePrefix + 'refresh_token');
		}

		/**
		 * Returns access token type stored in the local storage (e.g. Bearer).
		 *
		 * @returns {String}
		 */
		function getTokenType()
		{
			return clientOptions.rememberUser ? localStorage.getItem(clientOptions.localStoragePrefix + 'token_type') : sessionStorage.getItem(clientOptions.localStoragePrefix + 'token_type');
		}

		/**
		 * Removes acces token from local storage.
		 */
		function removeAccessToken()
		{
			if (clientOptions.rememberUser) {
				localStorage.removeItem(clientOptions.localStoragePrefix + 'access_token');
			} else {
				sessionStorage.removeItem(clientOptions.localStoragePrefix + 'access_token');
			}
		}

		/**
		 * Removes refresh token from local storage.
		 */
		function removeRefreshToken()
		{
			if (clientOptions.rememberUser) {
				localStorage.removeItem(clientOptions.localStoragePrefix + 'refresh_token');
			} else {
				sessionStorage.removeItem(clientOptions.localStoragePrefix + 'refresh_token');
			}
		}

		/**
		 * Saves token data in the local storage.
		 *
		 * @param {Object} tokenData Token data to persist
		 */
		function saveTokenData(tokenData)
		{
			if (clientOptions.rememberUser) {
				for (var tokenProperty in tokenData) {
					localStorage.setItem(clientOptions.localStoragePrefix + tokenProperty, tokenData[tokenProperty]);
				}
			} else {
				for (var tokenProperty in tokenData) {
					sessionStorage.setItem(clientOptions.localStoragePrefix + tokenProperty, tokenData[tokenProperty]);
				}
			}
			if (tokenData.expires_in || tokenData.token_expiry) {
				sessionStorage.setItem(clientOptions.localStoragePrefix + 'timeoutId', setTimeout(refreshAccessToken, 1000 * (tokenData.expires_in ? tokenData.expires_in : tokenData.token_expiry)));
			}
		}

		/**
		 * Removes token data from local storage.
		 */
		function clearTokenData()
		{
			if (clientOptions.rememberUser) {
				localStorage.removeItem(clientOptions.localStoragePrefix + 'access_token');
				localStorage.removeItem(clientOptions.localStoragePrefix + 'token_type');
				localStorage.removeItem(clientOptions.localStoragePrefix + 'token_expiry');
				localStorage.removeItem(clientOptions.localStoragePrefix + 'token_scope');
			} else {
				sessionStorage.removeItem(clientOptions.localStoragePrefix + 'access_token');
				sessionStorage.removeItem(clientOptions.localStoragePrefix + 'token_type');
				sessionStorage.removeItem(clientOptions.localStoragePrefix + 'token_expiry');
				sessionStorage.removeItem(clientOptions.localStoragePrefix + 'token_scope');
			}

			var timeoutId = sessionStorage.getItem(clientOptions.localStoragePrefix + 'timeoutId');

			if (timeoutId !== null) {
				clearTimeout(parseInt(timeoutId));
				sessionStorage.removeItem(clientOptions.localStoragePrefix + 'timeoutId');
			}
		}

		/**
		 * Sends refresh access token request to prolonge token life time.
		 */
		function refreshAccessToken()
		{
			// Refresh access token
			var tokenRequest = {
				grant_type: 'refresh_token',
				refresh_token: getRefreshToken()
			};
			var requestData = lastRequest;
			lastRequest = null;

			if (clientOptions.clientId) tokenRequest.client_id = clientOptions.clientId;
			if (clientOptions.clientSecret) tokenRequest.client_secret = clientOptions.clientSecret;

			var options = {
				successCallback: function(responseData, textStatus, jqXHR) {
					// Saving received token in the local storage
					saveTokenData(responseData);

					if (requestData !== null) {
						// Call last failed request
						that.send(requestData.path, requestData.method, requestData.requestBody, requestData.options);
					}
				}
			};

			that.send(clientOptions.tokenEndpoint, 'POST', tokenRequest, options);
		}

		/* Public methods */

		/**
		 * Sends a request to the API server.
		 *
		 * @param {String} path Path to the resource with optional request parameters (query string parameters)
		 * @param {String} method HTTP request method
		 * @param {any} requestBody Request body to send to the API
		 * @param {Object} options AJAX call options
		 */
		this.send = function(path, method, requestBody, options) {
			if (!requestBody || !requestBody.grant_type) {
				// Save current request data for token refreshing action
				lastRequest = {
					path: path,
					method: method,
					requestBody: requestBody,
					options: options
				};
			}

			var ajaxSettings = $.extend({
				type: method,
				data: requestBody !== null ? JSON.stringify(requestBody) : '',
				dataType: 'json',
				contentType: 'application/json',
				processData: false,
				async: true,
				xhrFields: {
					withCredentials: false
				},
				beforeSend: function (jqXHR) {
					if (getAccessToken()) {
						// Logged user - send authorization header with current access token
						jqXHR.setRequestHeader('Authorization', getTokenType() + ' ' + getAccessToken());
					}
					jqXHR.setRequestHeader('Accept', 'application/json');
				}
			}, options);

			var protocol = options.hasOwnProperty('protocol') ? options.protocol : clientOptions.protocol;
			var host = options.hasOwnProperty('host') ? options.host : clientOptions.host;

			// Send request
			$.ajax(
				protocol + '://' + host + path, ajaxSettings
			).done(function(responseData, textStatus, jqXHR) {
				// Call custom success callback
				if (ajaxSettings.successCallback) ajaxSettings.successCallback(responseData, textStatus, jqXHR);
			}).fail(function(jqXHR, textStatus, errorThrown) {
				var runErrorCallback = true;

				switch (jqXHR.status) {
					case 400:
						// BAD REQUEST
						if (jqXHR.responseJSON.error && jqXHR.responseJSON.error == 'invalid_grant') {
							// Probably token refresh request failed - run authorization logic
							clientOptions.authorizeCallback();
							runErrorCallback = false;
						}
						break;

					case 401:
						// UNAUTHORIZED

						// Logged user - use current authorization data from local storage
						var authParams = parseAuthenticateHeader(jqXHR.getResponseHeader('WWW-Authenticate'), getTokenType())

						if (authParams && authParams.error === undefined) {
							// Run authorization logic
							clientOptions.authorizeCallback();
							runErrorCallback = false;
						} else if (authParams && (authParams.error == 'invalid_token' || authParams.error == 'expired_token') && getRefreshToken()) {
							removeAccessToken();
							refreshAccessToken();
						} else if (!getRefreshToken()) {
							// Run authorization logic
							clientOptions.authorizeCallback();
							runErrorCallback = false;
						}
						break;

					case 403:
						// FORBIDDEN
						break;
				}

				// Call custom error callback
				if (runErrorCallback) {
					if (ajaxSettings.errorCallback) ajaxSettings.errorCallback(jqXHR, textStatus, errorThrown);
				} else {
					// Remove all OAuth 2.0 authorization data from local storage
					clearTokenData();
					// Remove refresh token from local storage
					removeRefreshToken();
				}
			}).always(function(responseData, textStatus, jqXHR) {
				// Call custom complete callback
				if (ajaxSettings.completeCallback) ajaxSettings.completeCallback(responseData, textStatus, jqXHR);
			});
		}

		/**
		 * Gets a new token from API OAuth 2.0 service.
		 *
		 * @param {Object} tokenRequest Token request data
		 * @param {Object} options AJAX call options
		 */
		this.getToken = function(tokenRequest, options) {
			if (clientOptions.clientId) tokenRequest.client_id = clientOptions.clientId;
			if (clientOptions.clientSecret) tokenRequest.client_secret = clientOptions.clientSecret;
			if (!options) options = {};
			if (options.rememberUser) {
				clientOptions.rememberUser = options.rememberUser;
				localStorage.setItem(clientOptions.localStoragePrefix + 'remember_user', clientOptions.rememberUser);
			}

			var successCallback = options.successCallback || null;
			options.successCallback = function(responseData, textStatus, jqXHR) {
				// OAuth 2.0 authorization - saving received authorization data in the local storage
				saveTokenData(responseData);
				// Call custom success callback
				if (successCallback) successCallback(responseData, textStatus, jqXHR);
			};

			this.send(clientOptions.tokenEndpoint, 'POST', tokenRequest, options);
		}

		/**
		 * Revokes current acces token.
		 *
		 * @param {Object} options AJAX call options
		 */
		this.revokeToken = function(options) {
			if (getAccessToken()) {
				if (!options) options = {};
				var successCallback = options.successCallback || null;

				options.successCallback = function(responseData, textStatus, jqXHR) {
					// Remove all OAuth 2.0 authorization data from local storage
					clearTokenData();
					// Remove refresh token from local storage
					removeRefreshToken();
					// Call custom success callback
					if (successCallback) successCallback(responseData, textStatus, jqXHR);
				};

				// Revoke access token
				this.send(
					clientOptions.revokeEndpoint, 'POST',
					{ token: getAccessToken(), token_type_hint: 'access_token' },
					options
				);
			}
		}

		/**
		 * Returns current access token type.
		 *
		 * @returns {String}
		 */
		this.getCurrentTokenType = function() {
			return getTokenType();
		}

		/**
		 * Returns current access token.
		 *
		 * @returns {String}
		 */
		this.getCurrentAccessToken = function() {
			return getAccessToken();
		}
	}

	return Artkosoft.OAuth2Client;
});
