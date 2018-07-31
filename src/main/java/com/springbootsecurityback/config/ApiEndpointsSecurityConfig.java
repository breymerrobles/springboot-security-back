package com.springbootsecurityback.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.springbootsecurityback.security.JwtAuthenticationEntryPoint;
import com.springbootsecurityback.security.JwtAuthenticationFilter;

@Configuration
@Order(1)
public class ApiEndpointsSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private JwtAuthenticationEntryPoint unauthorizedHandler;
	@Autowired
	private JwtAuthenticationFilter jwtAuthenticationFilter;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable().authorizeRequests().antMatchers(HttpMethod.POST, "/account/register")
				.permitAll().antMatchers(HttpMethod.POST, "/account/login").permitAll()
				.antMatchers(HttpMethod.GET, "/account/greet")
				// .hasAnyAuthority("ROLE_USER")
				.hasAnyAuthority("ROLE_ADMIN", "ROLE_USER").
				anyRequest().fullyAuthenticated().and().exceptionHandling()
				.authenticationEntryPoint(unauthorizedHandler)
				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER).and().httpBasic().and()
				.rememberMe();
		http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
	}

}