package com.waelsworld.userservice.controllers;

import com.waelsworld.userservice.Dto.*;
import com.waelsworld.userservice.exceptions.InvalidPasswordException;
import com.waelsworld.userservice.exceptions.UserAlreadyExistsException;
import com.waelsworld.userservice.exceptions.UserDoesNotExistsException;
import com.waelsworld.userservice.services.AuthService;
import com.waelsworld.userservice.models.SessionStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    AuthService authService;
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@RequestBody LoginRequestDto request){
//        System.out.println(request.getEmail() + request.getPassword());
//        System.out.println("login");
        try{
            return authService.login(request.getEmail(), request.getPassword());
            //return ResponseEntity.ok(userDto);
        }catch (UserDoesNotExistsException | InvalidPasswordException e){
            return ResponseEntity.status(401).body(null);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequestDto request){
        return authService.logout(request.getToken(), request.getUserId());
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDto> signUp(@RequestBody SignUpRequestDto request) {
        try{
            UserDto userDto = authService.signUp(request.getEmail(), request.getPassword());
            System.out.println(userDto.getEmail() + userDto.getPassword());
            return ResponseEntity.ok(userDto);
        }catch (UserAlreadyExistsException e){
            return ResponseEntity.status(409).body(null);
        }
    }

    @PostMapping("/validate")
    public ResponseEntity<SessionStatus> validateToken(ValidateTokenRequestDto request){
        SessionStatus sessionStatus = authService.validate(request.getToken(), request.getUserId());

        return ResponseEntity.ok(sessionStatus);
    }
}
