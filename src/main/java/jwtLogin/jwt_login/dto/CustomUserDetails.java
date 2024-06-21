package jwtLogin.jwt_login.dto;


import jwtLogin.jwt_login.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    // 초기화 하기
    private final UserEntity userEntity;

    public CustomUserDetails(UserEntity userEntity) {
        this.userEntity = userEntity;
    }


    // 권한 값
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {
                return userEntity.getRole();
            }
        });
        return collection;
    }

    // 비밀번호 값
    @Override
    public String getPassword() {

        return userEntity.getPassword();
    }

    // 사용자 아이디 값
    @Override
    public String getUsername() {
        return userEntity.getUserName();
    }

    // 계정의 만료 여부
    @Override
    public boolean isAccountNonExpired() {
        // true는 설정이 막히지 않았다라는 의미
        return true;
    }

    // 계정의 잠김 여부
    @Override
    public boolean isAccountNonLocked() {
        // true는 설정이 막히지 않았다라는 의미
        return true;
    }

    // 계정 비밀번호 만료 상태
    @Override
    public boolean isCredentialsNonExpired() {
        // true는 설정이 막히지 않았다라는 의미
        return true;
    }

    // 계정의 존재 유무
    @Override
    public boolean isEnabled() {
        // true는 설정이 막히지 않았다라는 의미
        return true;
    }
}
