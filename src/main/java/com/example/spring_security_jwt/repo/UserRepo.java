package com.example.spring_security_jwt.repo;


import com.example.spring_security_jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<com.example.spring_security_jwt.entity.User,Long> {

    public User findByUserId(String userId);

    public User findUserByUserId(String userId);
}
