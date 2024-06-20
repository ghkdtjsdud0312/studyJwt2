package jwtLogin.jwt_login.repository;

import jwtLogin.jwt_login.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity,Long> {

}
