package in.stephanelep.bonita.auth;

import java.io.Serializable;
import java.util.Map;

import org.bonitasoft.engine.authentication.AuthenticationConstants;
import org.bonitasoft.engine.authentication.AuthenticationException;
import org.bonitasoft.engine.authentication.GenericAuthenticationService;
import org.bonitasoft.engine.log.technical.TechnicalLogSeverity;
import org.bonitasoft.engine.log.technical.TechnicalLoggerService;
import org.bonitasoft.engine.sessionaccessor.STenantIdNotSetException;
import org.bonitasoft.engine.sessionaccessor.SessionAccessor;

public class PassthroughAuthenticationService implements GenericAuthenticationService {
	private TechnicalLoggerService logger;
	private SessionAccessor sessionAccessor;
	
	public PassthroughAuthenticationService(final TechnicalLoggerService logger, final SessionAccessor sessionAccessor) {
		this.logger = logger;
		this.sessionAccessor = sessionAccessor;
	}
	
	@Override
	public String checkUserCredentials(Map<String, Serializable> credentials) throws AuthenticationException {
		String username = String.valueOf(credentials.get(AuthenticationConstants.BASIC_USERNAME));
		try {
			logger.log(this.getClass(), TechnicalLogSeverity.INFO, "Authentication evidemment OK pour "+username+" sur le tenant "+this.sessionAccessor.getTenantId());
		} catch (STenantIdNotSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return username;
	}
}
