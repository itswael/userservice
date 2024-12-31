package com.waelsworld.userservice.services;

import com.waelsworld.userservice.Repositories.RoleRepository;
import com.waelsworld.userservice.models.Role;
import org.springframework.stereotype.Service;

@Service
public class RoleService {
    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public Role createRole(String name) {
        Role role = new Role();
        role.setRole(name);

        return roleRepository.save(role);
    }
}
