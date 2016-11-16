/*
MIT License

Copyright (c) 2014 Stéphane Lepin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
			logger.log(this.getClass(), TechnicalLogSeverity.INFO, "Auth obviously OK for "+username+" on tenant "+this.sessionAccessor.getTenantId());
		} catch (STenantIdNotSetException e) {
			e.printStackTrace();
		}
		return username;
	}
}
