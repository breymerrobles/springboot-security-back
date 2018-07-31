package com.springbootsecurityback.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import com.springbootsecurityback.security.CsrfHeaderFilter;
import com.springbootsecurityback.services.AppUserDetailsService;

/**
 * @author kamal berriga
 *
 */
@EnableWebSecurity
@Configuration
// Modifying or overriding the default spring boot security.
public class WebConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private AppUserDetailsService appUserDetailsService;
	@Autowired
	private Environment environment;
	
	@Autowired
	private CsrfTokenRepository csrfTokenRepository;
	
	@Autowired
	private CsrfHeaderFilter csrfHeaderFilter;
	
	

	// This method is for overriding the default AuthenticationManagerBuilder.
	// We can specify how the user details are kept in the application. It may
	// be in a database, LDAP or in memory.
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(appUserDetailsService);
	}



	// This method is for overriding some configuration of the WebSecurity
	// If you want to ignore some request or request patterns then you can
	// specify that inside this method
	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}

	// This method is used for override HttpSecurity of the web Application.
	// We can specify our authorization criteria inside this method.
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		 http
		
		 .regexMatcher(".*")
		 .authorizeRequests()
		 .anyRequest().authenticated()
		 .and()
		 .formLogin()

		 .and()
		 .logout().deleteCookies("JSESSIONID", "XSRF-TOKEN")
		 .and()
		 .csrf()
		 .csrfTokenRepository(csrfTokenRepository)
		 .and()
		 .addFilterAfter(csrfHeaderFilter, CsrfFilter.class)
		 .rememberMe()
		 ;

	}



}
