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

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;

public class JWTAuthConfigProvider implements AuthConfigProvider {
	
	public JWTAuthConfigProvider(AuthConfigFactory factory) {
		if (factory!=null) {
			// register an AuthConfigProvider class, a layer, an app context, a description
			factory.registerConfigProvider(this, null, null, null);
		}
	}

	@Override
	public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler handler) throws AuthException {
		return null;
	}

	@Override
	public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler handler) throws AuthException {
		return new JWTServerAuthConfig(layer, appContext, handler);
	}

	@Override
	public void refresh() {
	}

}
