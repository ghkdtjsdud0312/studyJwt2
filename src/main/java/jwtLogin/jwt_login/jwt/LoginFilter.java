package jwtLogin.jwt_login.jwt;

import jwtLogin.jwt_login.dto.CustomUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // AuthenticationManager 주입 받기
    private final AuthenticationManager authenticationManager;

    // JWTUtil 주입 받기
    private final JWTUtil jwtUtil;

    // 생성자 방식으로 받기
    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {

        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    // attemptAuthentication 메서드를 @Override 해줘야 한다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username, password 추출(obtain 메소드 사용)
        String username = obtainUsername(request);
        String password = obtainPassword(request);


        System.out.println("Attempting authentication for user: " + username);


        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함(인증 진행)
        // UsernamePasswordAuthenticationToken에 담아서 authenticationManager에 전달 해줘야 한다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);


        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }


    //로그인 성공시 실행 하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        // 유저 객체를 알아 내기(특정한 유저를 알아 볼 수 있다.)
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        // customUserDetails에서 유저 네임을 뽑아낸다.
        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        // role 값 구현
        String role = auth.getAuthority();

        // 토큰 만들어 토큰 받아옴
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // 헤더 부분에 담아 응답 해준다.
        response.addHeader("Authorization", "Bearer " + token);
    }

    //로그인 실패시 실행 하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        // 401 응답을 보내면 된다.
        response.setStatus(401);
    }
}
