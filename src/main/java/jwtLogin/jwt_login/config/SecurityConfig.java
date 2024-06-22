package jwtLogin.jwt_login.config;

import jwtLogin.jwt_login.jwt.JWTFilter;
import jwtLogin.jwt_login.jwt.JWTUtil;
import jwtLogin.jwt_login.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // security를 위한 것
@EnableWebSecurity
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    // JWTUtil 주입
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        // 세션 방식에서는 세션이 계속 항상 고정되기 때문에 csrf 공격이 필수적으로 방어를 해줘야 한다.
        // 하지만 jwt 방식은 세션을 스테이트리스 상태로 관리하기 때문에 csrf에 대한 공격을 방어하지 않아도 되서 기본적으로 disable 상태로 둔다.
        http
                .csrf().disable();

        //Form 로그인 방식 disable
        http
                .formLogin().disable();

        //http basic 인증 방식 disable
        http
                .httpBasic().disable();

        //경로별 인가 작업(admin controller)
        http
                .authorizeRequests()
                .antMatchers("/login", "/", "/join").permitAll() // 모든 권한 허용
                .antMatchers("/admin").hasRole("ADMIN") // 어드민이라는 권한을 가진 사용자만 접근 가능
                .anyRequest().authenticated(); // 그 외 나머지 요청에 대해서는 로그인한 사용자만 접근 가능

        // JWTFilter 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);


        // filter를 대체해서 등록 할 것이기 때문에 그 자리에 등록 하기 위해서 addFilterAt라는 메소드 사용
        // 위에서 authenticationManager 주입 받은 후 호출해서 가로 안에 넣어 준다.
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //세션 설정(jwt에서 중요한 방식)
        // session을 stateless 상태로 설정 해줘야 함
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();
    }

}
