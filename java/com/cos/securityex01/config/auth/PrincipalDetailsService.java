package com.cos.securityex01.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;

// 현재 시큐리티 설정에서 loginProcessingUrl("/login")을 걸어두었다.
// login 요청이 오면 자동으로 UserDetailsService 타입으로 loc되어 있는 loadUserByUsername 함수가 실행된다.
@Service
public class PrincipalDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;

	// 여기서 리턴해준 UserDtatils가 Authentication 내부에 자동으로 들어감
	// username이 로그인시 id의 input의 name과 일치하여야한다.(주의!!)
	// 일치하지 않을 경우 추가적인 내용 구현해야함
	// 또는 username에 해당하는 값을 securityConfig의 configure에서 .usernameParameter("username2")와 같이 변경해주어야한다.
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username);
		if(user == null) {
			return null;
		}

		/*
		Optional<User> userOptional = userRepository.findById(username);
            User user = userOptional.orElseThrow(() -> new UsernameNotFoundException(("msg.error.login.fail")));


		 ApiUserDetails rUserDetails = ApiUserDetails.builder()
                    .username(user.getId())
                    .password(user.getPassword())
                    .grantedAuthorities(user.getRole().getGrantedAuthorities())
                    .use(true)
                    .build();
		 */

		return new PrincipalDetails(user);
	}

}
