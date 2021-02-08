package com.cos.securityex01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 시큐리티 활성화(스프링 시큐리티 필터가 스프링 필터체인에 등록된다)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) // 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화
// securedEnabled = true : @Secured 활성화 => Controller단의 요청받는 메소드에 어노테이션을 통해 접근권한을 설정할 수 있다. ex) IndexController의 manager()
// prePostEnabled = true : @PreAuthorize,@PostAuthorize 활성화 => @Secured와 비슷한데 여러개의 권한을 지정하기에 유용하다.
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	// 패스워드 암호화에 사용된다.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
			.csrf().disable() // csrf 비활성화
			.and()
			.authorizeRequests() // 요청에 대한 권한설정
			.antMatchers("/user/**").authenticated() // 다음과 같은 요청에는 인증이 필요함
			.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // 인증 뿐만아니라 권한까지 인증되어야함
			.anyRequest().permitAll() // 나머지 요청에 대해서는 모두 허가
			.and()
			.formLogin()
			.loginPage("/loginForm") // 시큐리티가 낚아채는 로그인페이지가 시큐리티 기본 로그인 페이지가 아니라 직접 로그인 페이지 요청을 지정한다.
//			.usernameParameter("username2") // principalDetailsService에서 사용될 username의 이름지정
			.loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행한다.(컨트롤러단에서 '/login'에 대한 처리를 하지 않아도됨)
			.defaultSuccessUrl("/") // 로그인 성공했을 때 이동할 경로지정

	}
}





