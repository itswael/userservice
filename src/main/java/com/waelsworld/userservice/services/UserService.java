package com.waelsworld.userservice.services;

import com.waelsworld.userservice.Dto.UserDto;
import com.waelsworld.userservice.Repositories.RoleRepository;
import com.waelsworld.userservice.Repositories.UserRepository;
import com.waelsworld.userservice.models.Role;
import com.waelsworld.userservice.models.User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {
    UserRepository userRepository;
    RoleRepository roleRepository;
    public UserService(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    public UserDto getUserDetails(Long id) {
        return UserDto.from(this.userRepository.findById(id).orElse(null));
    }

    public UserDto setUserRoles(Long id, List<Long> roleIds) {
        Optional<User> optionalUser = this.userRepository.findById(id);
        if (optionalUser.isEmpty()) {
            return null;
        }
        List<Role> roles = this.roleRepository.findAllByIdIn(roleIds);
        User user = optionalUser.get();
        user.setRoles(Set.copyOf(roles));
        User savedUser = this.userRepository.save(user);
        return UserDto.from(savedUser);
    }
}
