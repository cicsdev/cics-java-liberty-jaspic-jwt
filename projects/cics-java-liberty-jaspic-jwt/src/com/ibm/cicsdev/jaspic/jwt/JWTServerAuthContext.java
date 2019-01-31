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

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthContext;

public class JWTServerAuthContext implements ServerAuthContext {

	private JWTServerAuthModule serverAuthModule;
	
	public JWTServerAuthContext(CallbackHandler handler) throws AuthException {
        serverAuthModule = new JWTServerAuthModule();
        serverAuthModule.initialize(null, null, handler, null); //requestPolicy, responsePolicy, handler, options
    }
	
	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		serverAuthModule.cleanSubject(messageInfo, subject);
	}

	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		return serverAuthModule.secureResponse(messageInfo, serviceSubject);
	}

	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
		return serverAuthModule.validateRequest(messageInfo, clientSubject, serviceSubject);
	}

}
 