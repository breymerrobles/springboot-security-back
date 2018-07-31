package com.springbootsecurityback.security.helper;

import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.springbootsecurityback.dto.LoginDTO;
import com.springbootsecurityback.security.JwtTokenProvider;
import com.springbootsecurityback.security.role.ROLE;
import com.springbootsecurityback.services.AppUserDetailsService;
import com.springbootsecurityback.util.SecurityConstants;

import io.jsonwebtoken.lang.Collections;

@Component
public class SecurityHelper {
	private static final Logger logger = LoggerFactory.getLogger(SecurityHelper.class);
	@Autowired
	private JwtTokenProvider tokenProvider;

	@Autowired
	private AppUserDetailsService appUserDetailsService;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	public UserDetails getUserDetailsFormBearerToken(final String bearerToken) {
		logger.info("Validating info from BearerToken {}", bearerToken);
		UserDetails userDetails = null;
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(SecurityConstants.TOKEN_PREFIX)) {
			final String jwt = bearerToken.substring(7, bearerToken.length());
			if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
				final String username = tokenProvider.getUserNameFromJWT(jwt);
				userDetails = appUserDetailsService.loadUserByUsername(username);
			}
		}
		logger.info("Validating info from BearerToken out : {}", userDetails);
		return userDetails;
	}

	public UserDetails getUserDetailsFormBasicToken(final String basicToken) {
		logger.info("Validating info from BasicToken {}", basicToken);
		UserDetails userDetails = null;
		if (StringUtils.hasText(basicToken) && basicToken.startsWith(SecurityConstants.LOGIN_TOKEN_PREFIX)) {

			userDetails = getUserDetailFromLoginPage(basicToken);
		}

		logger.info("Validating info from token BasicToken : {}", userDetails);
		return userDetails;
	}

	private UserDetails getUserDetailFromLoginPage(String basicToken) {
		logger.info("Gettin user from BasicToken {}", basicToken);
		basicToken = basicToken.substring(6, basicToken.length());
		final String decoded = new String(Base64.getDecoder().decode(basicToken));
		final String[] separeToken = decoded.split(SecurityConstants.LOGIN_TOKEN_SEPARATOR);
		UserDetails userDetails = appUserDetailsService.loadUserByUsername(separeToken[0]);
		if (userDetails != null) {
			logger.info("User Found {} from BasicToken {}", userDetails.toString(), basicToken);
			if (userDetails.getPassword() == null
					|| !bCryptPasswordEncoder.matches(separeToken[1], userDetails.getPassword())) {

				logger.info("User found {} but password does not match from BasicToken {}", userDetails.toString(),
						basicToken);
				userDetails = null;
			}
		}
		return userDetails;
	}
	
	public LoginDTO getLoginDTOFromBasicToken(final String encoded) {
		final UserDetails userDetails = getUserDetailsFormBasicToken(encoded);
		if (userDetails != null) {
			final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
					userDetails, null, userDetails.getAuthorities());
			authentication.setDetails(new WebAuthenticationDetailsSource());
			SecurityContextHolder.getContext().setAuthentication(authentication);
			final LoginDTO dtoLoginGenerated = new LoginDTO(this.jwtTokenProvider.generateToken(authentication),
					userDetails);

			SecurityContextHolder.getContext().setAuthentication(authentication);
			return dtoLoginGenerated;
		}
		return null;
	}

	public boolean validateRoutes(String role, List<String> routes, String route) {
		logger.info("Start validating URI {} for Role : {}.", route, role);
		final boolean validateRoute = routes.stream().anyMatch(r -> r.contains(route));
		logger.info("End of validate URI {} for Role : {} with result {} ", route, role, validateRoute);
		return validateRoute;
	}
}
