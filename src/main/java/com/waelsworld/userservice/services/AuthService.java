package com.waelsworld.userservice.services;

import com.waelsworld.userservice.Dto.UserDto;

import com.waelsworld.userservice.Repositories.SessionRepository;
import com.waelsworld.userservice.Repositories.UserRepository;
import com.waelsworld.userservice.exceptions.InvalidPasswordException;
import com.waelsworld.userservice.exceptions.UserDoesNotExistsException;
import com.waelsworld.userservice.models.Session;
import com.waelsworld.userservice.models.SessionStatus;
import com.waelsworld.userservice.models.User;
import com.waelsworld.userservice.exceptions.UserAlreadyExistsException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
//import net.bytebuddy.implementation.bytecode.Throw;
//import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMapAdapter;

import javax.crypto.SecretKey;
import java.util.*;

@Service
public class AuthService {
    private final SessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    public AuthService(UserRepository userRepository, SessionRepository sessionRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    public ResponseEntity<UserDto> login(String email, String password) throws UserDoesNotExistsException, InvalidPasswordException {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            throw new UserDoesNotExistsException("User with email: " + email + " not found.");
        }

        User user = userOptional.get();

//      for regular password validation
//        if (!user.getPassword().equals(password)) {
//            return null;
//        }

        // using bcrypt for password validation
        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new InvalidPasswordException("Password is incorrect");
        }

        // Regular Token generation can be done using random strings
//        String token = RandomStringUtils.randomAlphanumeric(30);

        // using JWT token generation
        Map<String, Object> jsonForJwt = new HashMap<>();
        jsonForJwt.put("email", user.getEmail());
        jsonForJwt.put("roles", user.getRoles());
        jsonForJwt.put("userId", user.getId());
        //jsonForJwt.put("expirationDate", new Date());
        //if(xx =!null)
        //jsonForJwt.put("createdAt" , new Date());
        MacAlgorithm alg = Jwts.SIG.HS256;
        SecretKey key = alg.key().build();
        String token = Jwts.builder()
                .claims(jsonForJwt)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 30))
                .signWith(key, alg)
                .compact();

        Session session = new Session();
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(token);
        session.setUser(user);
        sessionRepository.save(session);

        //        Map<String, String> headers = new HashMap<>();
        //        headers.put(HttpHeaders.SET_COOKIE, token);

        MultiValueMapAdapter<String, String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE, "auth-token:" + token);

        UserDto userDto = UserDto.from(user);
        //        response.getHeaders().add(HttpHeaders.SET_COOKIE, token);

        return new ResponseEntity<>(userDto, headers, HttpStatus.OK);
    }

    public ResponseEntity<Void> logout(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);

        if (sessionOptional.isEmpty()) {
            return null;
        }

        Session session = sessionOptional.get();
        session.setSessionStatus(SessionStatus.INACTIVE);
        sessionRepository.save(session);

        return ResponseEntity.ok().build();
    }

    public UserDto signUp(String email, String password) throws UserAlreadyExistsException {
        User userOptional = userRepository.findByEmail(email).orElse(null);
        if(userOptional != null){
            throw new UserAlreadyExistsException("User with email: " + email + " already exists.");
        }
        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));

        User savedUser = userRepository.save(user);

        return UserDto.from(savedUser);
    }

    public SessionStatus validate(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);

        MacAlgorithm alg = Jwts.SIG.HS256;
        SecretKey key = alg.key().build();
        Claims claims =
                Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();

        return sessionOptional.map(Session::getSessionStatus).orElse(null);
    }
}
