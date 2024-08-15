package com.example.myspringsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.and()
			.logout()
				.permitAll();
		// @formatter:on

	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(this.myAuthenticationProvider());
		
		// @formatter:off
		auth
			.inMemoryAuthentication()
				.passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder())
				.withUser("admin")
					.password("{noop}password")
					.roles("ADMIN").and()
				.withUser("user")
					.password("{noop}password")
					.roles("USER");
		// @formatter:on

		
	}
	
	@Bean
	public MyAuthenticationProvider myAuthenticationProvider() {
		return new MyAuthenticationProvider();
	}
	

}
