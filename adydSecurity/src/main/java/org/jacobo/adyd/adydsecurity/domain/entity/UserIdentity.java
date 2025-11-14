package org.jacobo.adyd.adydsecurity.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserIdentity {
    private String userId;
    private List<String> roles;
}