package com.cos.securityex01.config.auth;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.cos.securityex01.model.User;

import lombok.Data;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인 진행이 완료가 되면 시큐리티 session에 넣어주어야한다.(Security ContextHolder)
// 시큐리티 session에 들어갈 수 있는 오브젝트 타입은 정해져있다. => Authentication 타입 객체
// Authentication 안에는 User정보가 있어야 하는데 이 타입 역시 정해져있다. => UserDetails 타입 객체

// 정리 : Security Session => Authentication => UserDetails

@Data
public class PrincipalDetails implements UserDetails{

	private User user;

	public PrincipalDetails(User user) {
		super();
		this.user = user;
	}
	
	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	// 이 계정의 만료여부
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 이 계정의 잠김여부
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// 이 계정이 기간이 지났는지 여부
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// 이 계정의 활성화 여부
	@Override
	public boolean isEnabled() {
		return true;
	}

	// 해당 User의 권한을 리턴하는 곳(이 프로젝트에서는 user.getRole())
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collet = new ArrayList<GrantedAuthority>();
		collet.add(()->{ return user.getRole();});
		return collet;
	}
}
