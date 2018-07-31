package com.springbootsecurityback.controller;

import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.springbootsecurityback.dto.LoginDTO;
import com.springbootsecurityback.entities.User;
import com.springbootsecurityback.security.JwtTokenProvider;
import com.springbootsecurityback.security.helper.SecurityHelper;
import com.springbootsecurityback.security.role.ROLE;
import com.springbootsecurityback.services.UserService;
import com.springbootsecurityback.util.CustomErrorType;
import com.springbootsecurityback.util.SecurityConstants;

/**
 * @author kamal berriga
 *
 */
@RestController
@RequestMapping("account")
public class AccountController {

	public static final Logger logger = LoggerFactory.getLogger(AccountController.class);

	@Autowired
	private UserService userService;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
	private SecurityHelper securityUtil;

	// request method to create a new account by a guest
	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<?> createUser(@RequestBody User newUser) {
		if (userService.find(newUser.getUsername()) != null) {
			logger.error("username Already exist " + newUser.getUsername());
			return new ResponseEntity<Object>(
					new CustomErrorType("user with username " + newUser.getUsername() + "already exist "),
					HttpStatus.CONFLICT);
		}
		newUser.setRole(ROLE.ROLE_USER.name());
		// newUser.setRole(ROLE.ROLE_ADMIN.name());
		newUser.setPassword(bCryptPasswordEncoder.encode(newUser.getPassword()));
		logger.info("New User was created {}", newUser.toString());
		return new ResponseEntity<User>(userService.save(newUser), HttpStatus.CREATED);
	}

	// this is the login api/service

	@RequestMapping("/login")
	public ResponseEntity<?> login(@RequestHeader HttpHeaders headers) {
		final List<String> authorization = headers.get(SecurityConstants.HEADER_STRING);
		if (!authorization.isEmpty()) {
			final String encoded = authorization.get(0);
			logger.info("Headers found {}", encoded);

			final LoginDTO dtoLoginGenerated = securityUtil.getLoginDTOFromBasicToken(encoded);
			if (dtoLoginGenerated != null) {

				return new ResponseEntity<LoginDTO>(dtoLoginGenerated, HttpStatus.OK);
			} else {
				logger.error("User does not found.");
			}
		}
		logger.error("Headers does not found ");
		return new ResponseEntity<>(HttpStatus.LOCKED);
	}

	@RequestMapping(value = "/greet", method = RequestMethod.GET)
	public ResponseEntity<?> greet(@RequestParam(name = "name") String name) {

		return new ResponseEntity<String>("Hello : " + name, HttpStatus.OK);
	}

}
