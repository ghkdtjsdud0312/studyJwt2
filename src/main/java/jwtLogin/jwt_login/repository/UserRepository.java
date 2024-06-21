package jwtLogin.jwt_login.repository;

import jwtLogin.jwt_login.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity,Long> {
    // 아이디가 있는지 없는지 확인
    Boolean existsByUserName(String userName);

    //userName을 받아 DB 테이블에서 회원을 조회 하는 메소드 작성
    UserEntity findByUserName(String userName);
}
