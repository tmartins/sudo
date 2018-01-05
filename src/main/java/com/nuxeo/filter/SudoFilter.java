package com.nuxeo.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;

public class SudoFilter implements Filter {

    protected static final String SUDO_PATTERN = "/sudo/";

    protected static final String SUDO_REVERT = "exit";

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String uri = httpRequest.getRequestURI();

        if (uri.contains(SUDO_PATTERN)) {
            NuxeoPrincipal nxPrincipal = (NuxeoPrincipal) httpRequest.getSession().getAttribute("currentUser");
            if (canSudo(nxPrincipal)) {
                String[] parts = uri.split(SUDO_PATTERN);
                String clientLogin = parts[parts.length - 1];

                String targetURL = "/" + NXAuthConstants.SWITCH_USER_PAGE;
                httpRequest.setAttribute(NXAuthConstants.DISABLE_REDIRECT_REQUEST_KEY, true);
                if (!clientLogin.equals(SUDO_REVERT)) {
                    httpRequest.setAttribute(NXAuthConstants.SWITCH_USER_KEY, clientLogin);
                }
                httpRequest.setAttribute(NXAuthConstants.PAGE_AFTER_SWITCH, "");

                httpRequest.getRequestDispatcher(targetURL).forward(httpRequest, httpResponse);
                return;
            } else {
                httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
        } else {
            chain.doFilter(httpRequest, response);
        }
    }

    private boolean canSudo(NuxeoPrincipal principal) {
        if (principal == null) {
            return false;
        }
        if (principal.isAdministrator()) {
            return true;
        } else {
            String originating = principal.getOriginatingUser();
            if (originating == null) {
                return false;
            }
            UserManager um;
            try {
                um = Framework.getService(UserManager.class);
                NuxeoPrincipal org = um.getPrincipal(originating);
                return org.isAdministrator();
            } catch (Exception e) {
                return false;
            }
        }
    }

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void destroy() {
    }

}
