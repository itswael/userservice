package com.waelsworld.userservice.Repositories;

import com.waelsworld.userservice.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findById(Long id);
    Optional<Role> findByRole(String role);
    List<Role> findAllByIdIn(List<Long> roleIds);
}
