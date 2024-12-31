package com.waelsworld.userservice.Repositories;

import com.waelsworld.userservice.models.Session;
import com.waelsworld.userservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, Long> {
    Optional<Session> findByToken(String token);
    Optional<Session> findByUser(User user);
    void deleteByToken(String token);
    void deleteByUser(User user);
    Optional<Session> findByTokenAndUser_Id(String token, Long userId);
}
