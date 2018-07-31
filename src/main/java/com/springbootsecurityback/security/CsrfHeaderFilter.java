package com.springbootsecurityback.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import com.springbootsecurityback.util.SecurityConstants;


public class CsrfHeaderFilter extends OncePerRequestFilter {
	 private static final Logger logger = LoggerFactory.getLogger(CsrfHeaderFilter.class);
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.debug("request --headers");
		logger.debug(""+ request.getHeader(SecurityConstants.HEADER_STRING));
		
		logger.debug("request --headers");
		CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
	
		if (csrf != null) {
			
			Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
			String token = csrf.getToken();
		
			if (cookie == null || token != null && !token.equals(cookie.getValue())) {
				cookie = new Cookie("XSRF-TOKEN", token);
				cookie.setPath("/");
				response.addCookie(cookie);
			}
		}
		filterChain.doFilter(request, response);
	}
}
