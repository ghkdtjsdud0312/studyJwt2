package jwtLogin.jwt_login.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JoinDTO {
    // 사용자 아이디
    private String userName;

    // 비밀번호
    private String password;
}
