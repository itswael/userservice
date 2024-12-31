package com.waelsworld.userservice.Repositories;

import com.waelsworld.userservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.net.InterfaceAddress;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findById(Long id);

    Optional<User> findByEmail(String email);
}
