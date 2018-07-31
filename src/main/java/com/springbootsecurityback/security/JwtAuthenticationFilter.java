package com.springbootsecurityback.security;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springbootsecurityback.controller.AccountController;
import com.springbootsecurityback.security.helper.SecurityHelper;
import com.springbootsecurityback.security.role.ROLE;
import com.springbootsecurityback.util.SecurityConstants;


public class JwtAuthenticationFilter  extends OncePerRequestFilter {
	public static final Logger logger = LoggerFactory.getLogger(AccountController.class);
	@Autowired
	private SecurityHelper securityHelper;
	

	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			final UserDetails userDetails = getUserDetailsFromRequest(request);

			if (userDetails != null) {
//				
					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
							userDetails, userDetails.getPassword(), userDetails.getAuthorities());
					authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

					SecurityContextHolder.getContext().setAuthentication(authentication);
//				}

			}
		} catch (Exception ex) {
			logger.error("Could not set user authentication in security context", ex);
		}

		filterChain.doFilter(request, response);
	}

	private UserDetails getUserDetailsFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader(SecurityConstants.HEADER_STRING);
		logger.info(bearerToken);
		UserDetails userDetails = securityHelper.getUserDetailsFormBearerToken(bearerToken);
		return userDetails;
	}

}