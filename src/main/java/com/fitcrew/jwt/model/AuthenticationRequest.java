package com.fitcrew.jwt.model;

import com.fitcrew.FitCrewAppConstant.message.type.RoleType;
import lombok.*;

import java.io.Serializable;

@Getter
@Setter
@Builder(toBuilder = true)
@AllArgsConstructor(onConstructor = @__(@Builder))
@NoArgsConstructor
@ToString
public class AuthenticationRequest implements Serializable {

    private static final long serialVersionUID = 2118331620631970477L;
    private String email;
    private String password;
    private RoleType role;
}
