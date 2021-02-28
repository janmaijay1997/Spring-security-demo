package com.intent.SpringSecurityDemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		// this.disableLocalConfigureAuthenticationBldr = true;
		auth.inMemoryAuthentication().withUser("Admin").password("Admin@123").roles("ADMIN").and().withUser("User")
				.password("User@123").roles("USER");
	}

	@Bean
	public PasswordEncoder getPasswordEncoder() {

		return NoOpPasswordEncoder.getInstance();
	}

	@Override
	public void configure(HttpSecurity security) throws Exception {
				security.authorizeRequests().antMatchers("/user").hasRole("USER")
				.antMatchers("/admin").hasRole("ADMIN").antMatchers("/").permitAll().and().formLogin();

	}

}
