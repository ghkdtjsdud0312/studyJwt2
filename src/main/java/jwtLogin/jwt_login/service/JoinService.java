package jwtLogin.jwt_login.service;

import jwtLogin.jwt_login.dto.JoinDTO;
import jwtLogin.jwt_login.entity.UserEntity;
import jwtLogin.jwt_login.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    // repository 주입 받기
    private final UserRepository userRepository;

    // SecurityConfig 주입 받기(jwt)
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // service의 생성자 방식으로 repository 주입 받기
    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, BCryptPasswordEncoder bCryptPasswordEncoder1) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder1;
    }

    // 회원가입
    public void joinProcess(JoinDTO joinDTO) {
        String userName = joinDTO.getUserName(); // 아이디
        String password = joinDTO.getPassword(); // 비밀번호

        // 회원가입 시 아이디가 중복으로 존재하는지 체크(ok or no)
        Boolean isExist = userRepository.existsByUserName(userName);

        // 만약 있다면 다시 다른 아이디 생성하기
        if(isExist) {
            return;
        }

        // DB 내용 새로 생성하기 (회원가입 시)
        UserEntity data = new UserEntity();

        data.setUserName(userName); // 아이디
        data.setPassword(bCryptPasswordEncoder.encode(password)); // 비밀번호는 해킹 못하도록 암호화로 해독
        data.setRole("ROLE_ADMIN"); // 강제로 관리자로 줌

        userRepository.save(data); // 데이터 저장
    }
}
