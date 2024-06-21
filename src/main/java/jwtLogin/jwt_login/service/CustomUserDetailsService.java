package jwtLogin.jwt_login.service;

import jwtLogin.jwt_login.dto.CustomUserDetails;
import jwtLogin.jwt_login.entity.UserEntity;
import jwtLogin.jwt_login.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    // 주입 받기
    private final UserRepository userRepository;

    // 생성자 받기
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        // DB에서 조회
        UserEntity userData = userRepository.findByUserName(userName);

        if (userData != null) {
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
