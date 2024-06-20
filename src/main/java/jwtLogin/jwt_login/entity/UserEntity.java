package jwtLogin.jwt_login.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter
@Setter
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 아이디 값이 겹치지 않고 자동으로 잘 생성됨
    private Long id;

    // 사용자 이름
    @Column
    private String userName;

    // 비밀번호
    @Column
    private String password;

    // 사용자나 관리자 권한
    @Column
    private String role;

}
