package com.waelsworld.userservice.controllers;

import com.waelsworld.userservice.Dto.SetUserRolesRequestDto;
import com.waelsworld.userservice.Dto.UserDto;
import com.waelsworld.userservice.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserDetails(@PathVariable("id") Long id){
        try{
            UserDto userDto= userService.getUserDetails(id);
            if(userDto != null)
                return ResponseEntity.ok(userDto);
            else
                return ResponseEntity.notFound().build();
        }catch (Exception e){
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/{id}/roles")
    public ResponseEntity<UserDto> setUserRoles(@PathVariable("id") Long id, @RequestBody SetUserRolesRequestDto request){
        try {
            UserDto userDto = userService.setUserRoles(id, request.getRoleIds());
            if(userDto != null)
                return ResponseEntity.ok(userDto);
            else
                return ResponseEntity.notFound().build();
        }catch (Exception e){
            return ResponseEntity.notFound().build();
        }
    }
}
