/* Licensed Materials - Property of IBM                                   */
/*                                                                        */
/* SAMPLE                                                                 */
/*                                                                        */
/* (c) Copyright IBM Corp. 2019 All Rights Reserved                       */
/*                                                                        */
/* US Government Users Restricted Rights - Use, duplication or disclosure */
/* restricted by GSA ADP Schedule Contract with IBM Corp                  */
/*                                                                        */
package com.ibm.cicsdev.jaspic.jwt;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.websphere.security.UserRegistry;
import com.ibm.websphere.security.WSSecurityException;
import com.ibm.websphere.security.jwt.Claims;
import com.ibm.websphere.security.jwt.InvalidConsumerException;
import com.ibm.websphere.security.jwt.InvalidTokenException;
import com.ibm.websphere.security.jwt.JwtConsumer;
import com.ibm.websphere.security.jwt.JwtToken;
import com.ibm.wsspi.security.registry.RegistryHelper;
import com.ibm.wsspi.security.token.AttributeNameConstants;

public class JWTServerAuthModule implements ServerAuthModule {

	private CallbackHandler handler;
	@SuppressWarnings("rawtypes")
	protected static final Class[] supportedMessageTypes = new Class[] { HttpServletRequest.class, HttpServletResponse.class };

	
	@Override
	public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, @SuppressWarnings("rawtypes") Map options)
			throws AuthException {
		this.handler = handler;
	}
	
	@Override
	@SuppressWarnings("rawtypes")
	public Class[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}
	
	@Override
	public void cleanSubject(MessageInfo messageinfo, Subject subject) throws AuthException {
		if (subject!=null) {
			subject.getPrincipals().clear();
		}
	}

	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject subject) throws AuthException {
		return AuthStatus.SEND_SUCCESS;
	}

	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
		
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		Callback[] callbacks;
		
		// If no Basic Authentication is provided for JWT generation, or no JWT is provided to access resources.
		if (request.getHeader("Authorization")==null) {
			return AuthStatus.SEND_FAILURE;
		}
		
		// If the request is to get a JWT then use BasicAuth
		if (request.getRequestURI().matches("/jwt/ibm/api/(.*)/token") 
				&& request.getHeader("Authorization").matches("Basic ([a-zA-Z0-9]|-|_|=)+")) {
		
			try {
				// Get the user registry
				UserRegistry reg = RegistryHelper.getUserRegistry(null);
				// Retrieve the username and password from the BasicAuth
				String b64encoded = request.getHeader("Authorization").substring(6);
				String b64decoded = new String(Base64.getUrlDecoder().decode(b64encoded));
				String[] credentials  = b64decoded.split(":"); 
				if (credentials.length!=2) {
					return AuthStatus.SEND_FAILURE;
				}
				String securityName = credentials[0];
				String password = credentials[1];
				// Validate user credentials
				reg.checkPassword(securityName, password);
				String uniqueUsername = reg.getUniqueUserId(securityName);

				// when no callbacks are set to the CallbackHandler, an HashTable needs to be added to the Subject
				Hashtable<String,String> hashtable = new Hashtable<String,String>();
				hashtable.put(AttributeNameConstants.WSCREDENTIAL_UNIQUEID, uniqueUsername);
				hashtable.put(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME, securityName);
				hashtable.put(AttributeNameConstants.WSCREDENTIAL_PASSWORD, password);
				clientSubject.getPrivateCredentials().add(hashtable);
				
				return AuthStatus.SUCCESS;

			} catch (WSSecurityException | RemoteException e) {
				System.err.println("[JWTJASPIC] " + e.getMessage());
				throw (AuthException) new AuthException().initCause(e);
			}
		
		// Any other request with a JWT as Bearer token
		} else if (request.getHeader("Authorization").matches("Bearer ([a-zA-Z0-9]|-|_)+\\.([a-zA-Z0-9]|-|_)+\\.([a-zA-Z0-9]|-|_|=)+")) {

			try {
				// Get the JWT
				String jwtTokenString = request.getHeader("Authorization").split(" ")[1];
				// Create a JWTConsumer instance based on the configuration of `myJWTConsumer` from server.xml
				JwtConsumer jwtConsumer = new JwtConsumer("myJWTConsumer");
				// Validate the JWT
				JwtToken jwtTokenConsumer = jwtConsumer.createJwt(jwtTokenString);
				Claims jwtClaims = jwtTokenConsumer.getClaims();
				String user = jwtClaims.getSubject();
				System.out.println("[JWTJASPIC] JASPIC USER = " + user);
				
				UserRegistry reg = RegistryHelper.getUserRegistry(null);
				if(!reg.isValidUser(user)) {
					System.err.println("[JWTJASPIC] User=" + user + " doesn't exist in the User Registry.");
					return AuthStatus.SEND_FAILURE;					
				}
				
				ArrayList<String> groups = new ArrayList<>();
				if (jwtClaims.containsKey("groupIds")) {
					groups = jwtClaims.getClaim("groupIds", ArrayList.class);
					System.out.println("[JWTJASPIC] JASPIC GROUPS = " + groups);
				}
				String[] groups2 = new String[] {};
				// Convert ArrayList<String> to String[]
				groups2 = groups.toArray(groups2);
				
				callbacks = new Callback[] {
						// authenticated userID
						new CallerPrincipalCallback(clientSubject, user),
						// roles/groups
						new GroupPrincipalCallback(clientSubject, groups2)
				};
				handler.handle(callbacks);

			// InvalidConsumerException = thrown if the jwtConsumer ID cannot be found 
			// InvalidTokenException = thrown if the JWT is null or empty, or if there is an error while processing the token
			} catch (IOException | UnsupportedCallbackException | InvalidConsumerException | InvalidTokenException | WSSecurityException e) {
				System.err.println("[JWTJASPIC] " + e.getMessage());
				throw (AuthException) new AuthException().initCause(e);
			}
			return AuthStatus.SUCCESS;
			
		} else {
			// When there is no JWT 
			return AuthStatus.SEND_FAILURE;
		}
	}

}
