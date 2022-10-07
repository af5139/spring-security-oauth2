package com.security.security1.repository;

import com.security.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//crud 함수를 가지고 있음
//@repository어노테이션 없어도 ioc 가능 자동 빈 등록
public interface UserRepository extends JpaRepository<User,Integer> {
    //findBy 규칙 -> Username 문법
    //select * from user where username=1?
    public User findByUsername(String username);

    //select * from user where email=1?
    public User findByEmail(String email);
}
