package com.waelsworld.userservice.controllers;

import com.waelsworld.userservice.Dto.createRoleRequestDto;
import com.waelsworld.userservice.models.Role;
import com.waelsworld.userservice.services.RoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/roles")
public class RoleController {
    RoleService roleService;
    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    public ResponseEntity<Role> createRole(@RequestBody createRoleRequestDto request){
        try{
            Role role = roleService.createRole(request.getName());
            return ResponseEntity.ok(role);
        }catch (Exception e){
            return ResponseEntity.notFound().build();
        }
    }

}
