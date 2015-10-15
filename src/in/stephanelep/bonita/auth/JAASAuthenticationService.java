package in.stephanelep.bonita.auth;

import java.io.Serializable;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.*;

import org.bonitasoft.engine.authentication.AuthenticationConstants;
import org.bonitasoft.engine.authentication.AuthenticationException;
import org.bonitasoft.engine.authentication.GenericAuthenticationService;
import org.bonitasoft.engine.log.technical.TechnicalLogSeverity;
import org.bonitasoft.engine.log.technical.TechnicalLoggerService;
import org.bonitasoft.engine.sessionaccessor.STenantIdNotSetException;
import org.bonitasoft.engine.sessionaccessor.SessionAccessor;

public class JAASAuthenticationService implements GenericAuthenticationService {
	private TechnicalLoggerService logger;
	private SessionAccessor sessionAccessor;

	public JAASAuthenticationService(final TechnicalLoggerService logger, final SessionAccessor sessionAccessor) {
		this.logger = logger;
		this.sessionAccessor = sessionAccessor;
		this.logger.log(this.getClass(), TechnicalLogSeverity.DEBUG, "Initialization");
	}

	@Override
	public String checkUserCredentials(final Map<String, Serializable> credentials) throws AuthenticationException {
		long tenantId;
		LoginContext lc;

		final String authUsername = String.valueOf(credentials.get(AuthenticationConstants.BASIC_USERNAME));
		final String authPassword = String.valueOf(credentials.get(AuthenticationConstants.BASIC_PASSWORD));

		String username = authUsername;

		try {
			tenantId = this.sessionAccessor.getTenantId();
			lc = new LoginContext("BonitaAuthentication-"+tenantId, new CallbackHandler(){
				public void handle(Callback[] callbacks) {
					for(int i = 0; i < callbacks.length; i++) {
						if(callbacks[i] instanceof NameCallback) {
							NameCallback nc = (NameCallback)callbacks[i];
							nc.setName(authUsername);
						}
						else if(callbacks[i] instanceof PasswordCallback) {
							PasswordCallback pc = (PasswordCallback)callbacks[i];
							pc.setPassword(authPassword.toCharArray());
						}
					}
				}
			});

			lc.login();

			logger.log(this.getClass(), TechnicalLogSeverity.DEBUG, "Auth success for user "+username);
			return username;
		}
		catch (LoginException | STenantIdNotSetException e) {
			logger.log(this.getClass(), TechnicalLogSeverity.ERROR, "Auth failure for user "+username+": "+e.getMessage());
			throw new AuthenticationException();
		}
		catch(Exception e) {
			logger.log(this.getClass(), TechnicalLogSeverity.ERROR, "Unknown exception "+e.getClass().toString()+": "+e.getMessage());
		}

		return null; 
	}
}
