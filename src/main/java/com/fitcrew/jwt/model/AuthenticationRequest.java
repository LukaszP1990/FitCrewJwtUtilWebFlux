package com.fitcrew.jwt.model;

import com.fitcrew.FitCrewAppConstant.message.ValidationErrorMessage;
import com.fitcrew.FitCrewAppConstant.message.type.RoleType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;
import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationRequest implements Serializable {

    @NotNull(message = ValidationErrorMessage.DATE_OF_BIRTH_ERROR_MESSAGE)
    private String email;

    @NotNull(message = ValidationErrorMessage.PASSWORD_ERROR_MESSAGE)
    private String password;

    @NotNull(message = ValidationErrorMessage.ROLE_ERROR_MESSAGE)
    private RoleType role;
}
