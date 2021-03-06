package org.apereo.cas.web.flow;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Performs a basic check if an authentication request for a provided service is authorized to proceed
 * based on the registered services registry configuration (or lack thereof).
 *
 * @author Dmitriy Kopylenko
 * @since 3.5.1
 **/
@Slf4j
@AllArgsConstructor
public class ServiceAuthorizationCheck extends AbstractAction {
    
    private final ServicesManager servicesManager;
    private final AuthenticationServiceSelectionPlan authenticationRequestServiceSelectionStrategies;

    @Override
    protected Event doExecute(final RequestContext context) {
        final WebApplicationService serviceInContext = WebUtils.getService(context);
        final Service service = authenticationRequestServiceSelectionStrategies.resolveService(serviceInContext);
        if (service == null) {
            return success();
        }

        if (this.servicesManager.getAllServices().isEmpty()) {
            final String msg = String.format("No service definitions are found in the service manager. "
                    + "Service [%s] will not be automatically authorized to request authentication.", service.getId());
            LOGGER.warn(msg);
            throw new UnauthorizedServiceException(UnauthorizedServiceException.CODE_EMPTY_SVC_MGMR, msg);
        }
        final RegisteredService registeredService = this.servicesManager.findServiceBy(service);

        if (registeredService == null) {
            final String msg = String.format("Service Management: missing service. "
                    + "Service [%s] is not found in service registry.", service.getId());
            LOGGER.warn(msg);
            throw new UnauthorizedServiceException(UnauthorizedServiceException.CODE_UNAUTHZ_SERVICE, msg);
        }
        if (!registeredService.getAccessStrategy().isServiceAccessAllowed()) {
            final String msg = String.format("Service Management: Unauthorized Service Access. "
                    + "Service [%s] is not allowed access via the service registry.", service.getId());

            LOGGER.warn(msg);

            WebUtils.putUnauthorizedRedirectUrlIntoFlowScope(context,
                    registeredService.getAccessStrategy().getUnauthorizedRedirectUrl());
            throw new UnauthorizedServiceException(UnauthorizedServiceException.CODE_UNAUTHZ_SERVICE, msg);
        }

        return success();
    }
}
