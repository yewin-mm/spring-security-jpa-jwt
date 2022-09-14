package pers.yewin.springsecurityjwt.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.model
 */

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Users {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String email;
    private String password;
    @ManyToMany(fetch = FetchType.EAGER) // many users can have many roles, (one user can have many roles, one role can have many users)
    private Collection<Role> roleList = new ArrayList<>();

    // you can add createdDate and updatedDate, description, address, phone, etc. fields, here I don't add those fields as this is demo project.

    // you can also add deleted column for logical deleting user.
}
