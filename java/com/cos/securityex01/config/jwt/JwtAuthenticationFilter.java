package com.cos.securityex01.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.securityex01.config.auth.PrincipalDetails;
import com.cos.securityex01.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// 원래 '/login' 요청해서 username, password 전송하면
// UsernamePasswordAuthenticationFilter 동작을 함
// 만약 시큐리티에서 .formLogin()을 disable()했다면 직접 등록해주어야함
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, ObjectMapper objectMapper) {
        this.authenticationManager = authenticationManager;
        this.objectMapper = objectMapper;
    }

    // '/login' 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("%%%%%%%%%%%%%%JwtAuthenticationFilter.attemptAuthentication");
        // 1. username, password 받아서
        try {
//            ObjectMapper om = new ObjectMapper(); // json 데이터를 변환해줌

            UsernameAndPasswordAuthenticationRequest usernameAndPasswordAuthenticationRequest =
                    objectMapper.readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
//            UsernameAndPasswordAuthenticationRequest usernameAndPasswordAuthenticationRequest = new UsernameAndPasswordAuthenticationRequest();
//            usernameAndPasswordAuthenticationRequest.setUsername(request.getParameter("username"));
//            usernameAndPasswordAuthenticationRequest.setPassword(request.getParameter("password"));
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(usernameAndPasswordAuthenticationRequest.getUsername(),usernameAndPasswordAuthenticationRequest.getPassword());

            // PrincipalDetailsService의 loadUserByUsername()가 실행된다.
            // authentication 객체에 결과가 잘 반환되었으면 로그인에 성공한 것이다.
            // => DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            // authentication session 영역에 저장한다.
            return authentication;

        } catch (Exception e) {
            e.printStackTrace();
        }

        // 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하면 PrincipalDetailsService의 loadUserByUsername()가 실행된다.

        // 3. PrincipalDetails를 세션에 담고(담아주어야 권한관리가 된다!!)

        // 4. JWT토큰을 만들어서 응답해주면 됨됨
       return null;
    }

    // attemptAuthentication 실행 후 인증이 성공했으면 실행되는 메소드
    // JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response 해준다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10))) // 토큰 만료시간 10분
        .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization","Bearer " + jwtToken);


        super.successfulAuthentication(request, response, chain, authResult);
    }
}
