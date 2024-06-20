package jwtLogin.jwt_login.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // security를 위한 것
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        // 세션 방식에서는 세션이 계속 항상 고정되기 때문에 csrf 공격이 필수적으로 방어를 해줘야 한다.
        // 하지만 jwt 방식은 세션을 스테이트리스 상태로 관리하기 때문에 csrf에 대한 공격을 방어하지 않아도 되서 기본적으로 disable 상태로 둔다.
        http
                .csrf().disable();

        //From 로그인 방식 disable
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

        //세션 설정(jwt에서 중요한 방식)
        // session을 stateless 상태로 설정 해줘야 함
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();
    }

}
