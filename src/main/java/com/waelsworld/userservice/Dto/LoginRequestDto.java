package com.waelsworld.userservice.Dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequestDto {
    String email;
    String password;
}
