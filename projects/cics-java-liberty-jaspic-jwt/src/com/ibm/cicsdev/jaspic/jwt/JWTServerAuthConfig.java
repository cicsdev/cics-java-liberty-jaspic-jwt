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

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;


public class JWTServerAuthConfig implements ServerAuthConfig {

	private String layer;
    private String appContext;
    private CallbackHandler handler;
    
    public JWTServerAuthConfig(String layer, String appContext, CallbackHandler handler) {
        this.layer = layer;
        this.appContext = appContext;
        this.handler = handler;
    }
    
	@Override
	public String getAppContext() {
		return appContext;
	}

	@Override
	public String getAuthContextID(MessageInfo arg0) {
		return appContext;
	}

	@Override
	public String getMessageLayer() {
		return layer;
	}

	@Override
	public boolean isProtected() {
		return false;
	}

	@Override
	public void refresh() {
	}

	@Override
	public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject, @SuppressWarnings("rawtypes") Map properties) throws AuthException {
		return new JWTServerAuthContext(handler);
	}

}
