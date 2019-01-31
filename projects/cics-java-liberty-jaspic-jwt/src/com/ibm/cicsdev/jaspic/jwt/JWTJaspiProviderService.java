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

import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;

import com.ibm.wsspi.security.jaspi.ProviderService;

public class JWTJaspiProviderService implements ProviderService {

	@Override
	public AuthConfigProvider getAuthConfigProvider(AuthConfigFactory factory) {
		
		return new JWTAuthConfigProvider(factory);
	}

}
