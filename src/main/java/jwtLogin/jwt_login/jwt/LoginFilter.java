package jwtLogin.jwt_login.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // 주입 받기
    private final AuthenticationManager authenticationManager;

    // 생성자 방식으로 받기
    public LoginFilter(AuthenticationManager authenticationManager) {

        this.authenticationManager = authenticationManager;
    }

    // attemptAuthentication 메서드를 @Override 해줘야 한다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username, password 추출(obtain 메소드 사용)
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함(인증 진행)
        // UsernamePasswordAuthenticationToken에 담아서 authenticationManager에 전달 해줘야 한다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }


    //로그인 성공시 실행 하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

    }

    //로그인 실패시 실행 하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

    }
}
